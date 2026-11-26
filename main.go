package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/musix/backhaul/cmd"
	"github.com/musix/backhaul/internal/utils"
)

var (
	logger     = utils.NewLogger("info")
	configPath *string
	runMu      sync.Mutex
	runCtx     context.Context
	runCancel  context.CancelFunc
)

// Define the version of the application
const version = "v1.1.0"

func main() {
	configPath = flag.String("c", "", "path to the configuration file (TOML format)")
	showVersion := flag.Bool("v", false, "print the version and exit")

	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if *configPath == "" {
		logger.Fatalf("Usage: %s -c /path/to/config.toml", flag.CommandLine.Name())
	}

	if err := cmd.ValidateConfig(*configPath); err != nil {
		logger.Fatalf("invalid configuration: %v", err)
	}

	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()

	runMu.Lock()
	runCtx, runCancel = context.WithCancel(appCtx)
	curCtx := runCtx
	runMu.Unlock()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go cmd.Run(*configPath, curCtx)
	go hotReload(appCtx)

	<-sigChan
	logger.Info("received shutdown signal, stopping...")

	runMu.Lock()
	if runCancel != nil {
		runCancel()
	}
	runMu.Unlock()
	appCancel()

	time.Sleep(1 * time.Second)
}

func hotReload(appCtx context.Context) {
	lastModTime, err := getLastModTime(*configPath)
	if err != nil {
		logger.Errorf("hot-reload disabled (stat failed): %v", err)
		return
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-appCtx.Done():
			return
		case <-ticker.C:
			modTime, err := getLastModTime(*configPath)
			if err != nil {
				logger.Errorf("Error checking file modification time: %v", err)
				continue
			}

			if modTime.After(lastModTime) {
				lastModTime = modTime
				// Validate new config BEFORE shutting down the running instance!
				if err := cmd.ValidateConfig(*configPath); err != nil {
					logger.Errorf("Config file changed but is invalid — keeping active tunnel running: %v", err)
					continue
				}

				logger.Info("Config file changed and validated, reloading application...")
				runMu.Lock()
				if runCancel != nil {
					runCancel()
				}
				runMu.Unlock()

				select {
				case <-appCtx.Done():
					return
				case <-time.After(1500 * time.Millisecond):
				}

				runMu.Lock()
				runCtx, runCancel = context.WithCancel(appCtx)
				newCtx := runCtx
				runMu.Unlock()

				go cmd.Run(*configPath, newCtx)
			}
		}
	}
}

func getLastModTime(file string) (time.Time, error) {
	absPath, _ := filepath.Abs(file)
	fileInfo, err := os.Stat(absPath)
	if err != nil {
		return time.Time{}, err
	}
	return fileInfo.ModTime(), nil
}
