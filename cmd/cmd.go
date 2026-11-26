package cmd

import (
	"context"
	"fmt"

	"github.com/musix/backhaul/config"
	"github.com/musix/backhaul/internal/client"
	"github.com/musix/backhaul/internal/server"
	"github.com/musix/backhaul/internal/utils"
	"github.com/musix/backhaul/internal/utils/handlers"

	"github.com/BurntSushi/toml"
)

var (
	logger = utils.NewLogger("info")
)

// ValidateConfig checks whether a TOML file parses and defines a valid server or client config.
func ValidateConfig(configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	if cfg.Server.BindAddr == "" && cfg.Client.RemoteAddr == "" {
		return fmt.Errorf("neither [server].bind_addr nor [client].remote_addr is set")
	}
	return nil
}

func Run(configPath string, ctx context.Context) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		logger.Errorf("failed to load configuration: %v", err)
		return
	}

	applyDefaults(cfg)

	configType := ""
	if cfg.Server.BindAddr != "" {
		configType = "server"
	} else if cfg.Client.RemoteAddr != "" {
		configType = "client"
	} else {
		logger.Error("neither server nor client configuration is properly set.")
		return
	}

	switch configType {
	case "server":
		if !cfg.Server.SkipOptz {
			ApplyTCPTuning()
		}
		handlers.SetGlobalRateLimitMbps(cfg.Server.RateLimitMbps)

		srv := server.NewServer(&cfg.Server, ctx)
		go srv.Start()

		<-ctx.Done()
		srv.Stop()
		logger.Println("shutting down server...")

	case "client":
		if !cfg.Client.SkipOptz {
			ApplyTCPTuning()
		}
		handlers.SetGlobalRateLimitMbps(cfg.Client.RateLimitMbps)

		clnt := client.NewClient(&cfg.Client, ctx)
		go clnt.Start()

		<-ctx.Done()
		clnt.Stop()
		logger.Println("shutting down client...")

	default:
		logger.Error("neither server nor client configuration is properly set.")
	}
}

func loadConfig(configPath string) (*config.Config, error) {
	var cfg config.Config
	if _, err := toml.DecodeFile(configPath, &cfg); err != nil {
		return &cfg, err
	}
	return &cfg, nil
}
