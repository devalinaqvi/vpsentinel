package ports

import (
	"os"
	"path/filepath"
	"strings"
)

type procInfo struct {
	PID  string
	Comm string
}

func buildInodeProcessMap(procRoot string) map[string]procInfo {
	m := map[string]procInfo{}

	pidDirs, err := filepath.Glob(filepath.Join(procRoot, "[0-9]*"))
	if err != nil {
		return m
	}
	for _, pidDir := range pidDirs {
		fdDirs := filepath.Join(pidDir, "fd")
		entries, err := os.ReadDir(fdDirs)
		if err != nil {
			continue
		}
		comm := readComm(filepath.Join(pidDir, "comm"))
		pid := filepath.Base(pidDir)
		for _, entry := range entries {
			link, err := os.Readlink(filepath.Join(fdDirs, entry.Name()))
			if err != nil {
				continue
			}
			if after, ok := strings.CutPrefix(link, "socket:["); ok {
				inode := strings.TrimSuffix(after, "]")
				m[inode] = procInfo{PID: pid, Comm: comm}
			}
		}
	}
	return m
}

func readComm(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
