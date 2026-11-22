//go:build !linux

package main

import "testing"

func withReaping(*testing.T) {}
