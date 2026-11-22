//go:build race

package main

// raceEnabled: the race detector maps its shadow memory as data, so a race-built binary cannot run under RLIMIT_DATA.
const raceEnabled = true
