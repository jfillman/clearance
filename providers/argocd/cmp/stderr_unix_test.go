//go:build unix

package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A plugin run stopped by SIGTERM (Argo CD's exec timeout) mid-run leaves the lines it held on stderr, then a line
// naming the signal, and exits 128+15.
func TestASIGTERMLeavesTheHeldLines(t *testing.T) {
	c := exec.Command(os.Args[0], "-test.run=^$")
	c.Env = append(os.Environ(), "CMP_TEST_STDERR_SIGNAL=1")
	var stderr bytes.Buffer
	c.Stderr = &stderr
	stdout, err := c.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Process.Kill() })
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- line
	}()
	select {
	case line := <-ready:
		if line != "ready\n" {
			t.Fatalf("the child said %q", line)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the child never became ready")
	}
	if err := c.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err = c.Wait()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 128+int(syscall.SIGTERM) {
		t.Fatalf("exit: %v, want %d", err, 128+int(syscall.SIGTERM))
	}
	got := stderr.String()
	held := strings.Index(got, "clearance-cmp: WARNING held before the kill\n")
	stopped := strings.Index(got, "clearance-cmp: WARNING stopped by terminated after ")
	if held < 0 || stopped < held {
		t.Fatalf("the held line, then the signal's, are not on stderr:\n%s", got)
	}
}
