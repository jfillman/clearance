//go:build unix

package main

import "syscall"

// freeBytes is the space an unprivileged writer has left on the volume holding dir.
func freeBytes(dir string) (int64, bool) {
	var st syscall.Statfs_t
	if syscall.Statfs(dir, &st) != nil {
		return 0, false
	}
	return int64(st.Bavail) * int64(st.Bsize), true
}
