package cgroup

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
)

func getStatGeneric(statName, sysfsPrefix, cgroupPath, cgroupGrepLine string) (int64, error) {
	data, err := getFileContents(statName, sysfsPrefix, cgroupPath, cgroupGrepLine)
	if err != nil {
		return 0, err
	}
	data = strings.TrimSpace(data)
	n, err := strconv.ParseInt(data, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("cannot parse %q: %w", cgroupPath, err)
	}
	return n, nil
}

func getFileContents(statName, sysfsPrefix, cgroupPath, cgroupGrepLine string) (string, error) {
	// Try reading the stat from the process's own cgroup subpath first.
	// This prevents root cgroup files from shadowing service-level limits on hosts
	// where root sysfs files are readable (e.g. systemd slices).
	if cgroupData, err := os.ReadFile(cgroupPath); err == nil {
		if subPath, err := grepFirstMatch(string(cgroupData), cgroupGrepLine, 2, ":"); err == nil {
			filepath := path.Join(sysfsPrefix, subPath, statName)
			if data, err := os.ReadFile(filepath); err == nil {
				return string(data), nil
			}
		}
	}
	// Fall back to reading from sysfsPrefix directly (e.g. container mounts or root cgroup).
	filepath := path.Join(sysfsPrefix, statName)
	data, err := os.ReadFile(filepath)
	if err == nil {
		return string(data), nil
	}
	return "", err
}

// readCgroupV2SubPath reads cgroupv2 sub-path
// for example 0::/user.slice/user-1000.slice/session-5.scope
// See https://www.freedesktop.org/software/systemd/man/latest/systemd.slice.html
// and https://docs.oracle.com/en/operating-systems/oracle-linux/9/systemd/SystemdMngCgroupsV2.html#SystemdScopes
func readCgroupV2SubPath(cgroupPath string) (string, error) {
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return "", err
	}
	return grepFirstMatch(string(data), "", 2, ":")
}

// grepFirstMatch searches match line at data and returns item from it by index with given delimiter.
func grepFirstMatch(data string, match string, index int, delimiter string) (string, error) {
	lines := strings.SplitSeq(string(data), "\n")
	for s := range lines {
		if !strings.Contains(s, match) {
			continue
		}
		parts := strings.Split(s, delimiter)
		if index < len(parts) {
			return strings.TrimSpace(parts[index]), nil
		}
	}
	return "", fmt.Errorf("cannot find %q in %q", match, data)
}
