package safety

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

type Guard struct {
	blockedDevices     []string
	blockedPaths       []string
	confirmDestructive bool
}

var destructiveCmdPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(?:mkfs(?:\.\w+)?|fdisk|parted|sfdisk|cfdisk|gdisk|wipefs|shred|cryptsetup)\b`),
	regexp.MustCompile(`\bdd\b[^;|&\n]*\bof=`),
}

func NewGuard(blockedDevices, blockedPaths []string, confirmDestructive bool) *Guard {
	return &Guard{
		blockedDevices:     blockedDevices,
		blockedPaths:       blockedPaths,
		confirmDestructive: confirmDestructive,
	}
}

func (g *Guard) CheckPath(targetPath string) error {
	if g == nil || targetPath == "" {
		return nil
	}
	cleaned := filepath.Clean(targetPath)

	for _, dev := range g.blockedDevices {
		devClean := filepath.Clean(dev)
		if cleaned == devClean || strings.HasPrefix(cleaned, devClean+"/") || strings.HasPrefix(cleaned, devClean) && strings.HasPrefix(devClean, "/dev/") {
			return fmt.Errorf("safety guard blocked access to protected device %s (target: %s)", devClean, cleaned)
		}
	}

	for _, bp := range g.blockedPaths {
		bpClean := filepath.Clean(bp)
		if cleaned == bpClean || strings.HasPrefix(cleaned, bpClean+"/") {
			return fmt.Errorf("safety guard blocked access to protected path %s (target: %s)", bpClean, cleaned)
		}
	}

	return nil
}

func (g *Guard) CheckCommand(command string) error {
	if g == nil || command == "" {
		return nil
	}

	for _, dev := range g.blockedDevices {
		devClean := strings.TrimSpace(dev)
		if devClean == "" {
			continue
		}
		if strings.Contains(command, devClean) {
			return fmt.Errorf("safety guard blocked command referencing protected device %s", devClean)
		}
		shortDev := strings.TrimPrefix(devClean, "/dev/")
		if shortDev != devClean {
			for _, pat := range destructiveCmdPatterns {
				if pat.MatchString(command) && strings.Contains(command, shortDev) {
					return fmt.Errorf("safety guard blocked disk command referencing %s", shortDev)
				}
			}
		}
	}

	for _, bp := range g.blockedPaths {
		bpClean := strings.TrimSpace(bp)
		if bpClean != "" && strings.Contains(command, bpClean) {
			return fmt.Errorf("safety guard blocked command referencing protected path %s", bpClean)
		}
	}

	return nil
}

func (g *Guard) RequireDeleteConfirmation(confirmed bool, target string) error {
	if g == nil || !g.confirmDestructive {
		return nil
	}
	if !confirmed {
		return fmt.Errorf("deletion of %q requires confirm=true parameter", target)
	}
	return nil
}
