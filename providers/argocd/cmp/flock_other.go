//go:build !unix

package main

import "os"

// No file lock off unix (the sidecar is Linux): renders of one commit may each fetch it, and rename-wins keeps the
// entry whole.
func tryLock(*os.File) (bool, error) { return true, nil }

func unlock(*os.File) {}
