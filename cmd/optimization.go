package cmd

import (
	"fmt"
	"os/exec"
	"runtime"
	"syscall"
)

func ApplyTCPTuning() {
	if runtime.GOOS != "linux" {
		logger.Info("Non-Linux system detected, skipping TCP optimizations.")
		return
	}

	logger.Info("Applying TCP optimizations for Linux...")

	bufferSizes := []int{
		64 * 1024 * 1024,
		32 * 1024 * 1024,
		16 * 1024 * 1024,
	}

	for _, size := range bufferSizes {
		if err := exec.Command("sysctl", "-w", fmt.Sprintf("net.core.rmem_max=%d", size)).Run(); err == nil {
			logger.Debugf("Set rmem_max to %d", size)
			break
		}
	}
	for _, size := range bufferSizes {
		if err := exec.Command("sysctl", "-w", fmt.Sprintf("net.core.wmem_max=%d", size)).Run(); err == nil {
			logger.Debugf("Set wmem_max to %d", size)
			break
		}
	}

	commands := [][]string{
		{"sysctl", "-w", "net.ipv4.ip_local_port_range=1024 65535"},
		{"sysctl", "-w", "net.ipv4.tcp_tw_reuse=1"},
		{"sysctl", "-w", "net.ipv4.tcp_fin_timeout=15"},
		{"sysctl", "-w", "net.core.somaxconn=65536"},
		{"sysctl", "-w", "net.ipv4.tcp_max_syn_backlog=20480"},
		{"sysctl", "-w", "net.ipv4.tcp_window_scaling=1"},
		{"sysctl", "-w", "net.ipv4.tcp_fastopen=3"},
		{"sysctl", "-w", "net.ipv4.tcp_notsent_lowat=32768"},
		{"sysctl", "-w", "net.core.rmem_default=262144"},
		{"sysctl", "-w", "net.core.wmem_default=262144"},
	}

	for _, c := range commands {
		if err := exec.Command(c[0], c[1:]...).Run(); err != nil {
			logger.Debugf("Skipped TCP tuning %v: %v", c, err)
		}
	}

	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
		if rLimit.Max < 1048576 {
			rLimit.Max = 1048576
		}
		rLimit.Cur = rLimit.Max
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
			logger.Debugf("Skipped setting Rlimit: %v", err)
		}
	}
}
