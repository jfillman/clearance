//go:build !unix

package main

func freeBytes(string) (int64, bool) { return 0, false }
