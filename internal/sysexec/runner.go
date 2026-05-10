// Package sysexec wraps outbound command execution (wg, nft, ip, ping, nc,
// tcpdump, systemctl) behind a Runner interface so tests can use fixtures
// and dev machines don't need Linux binaries.
package sysexec

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// Result is the outcome of a single command invocation.
type Result struct {
	Cmd      string
	Args     []string
	Stdin    string
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
	Duration time.Duration
}

// Runner executes system commands. Implementations must be safe for
// concurrent use.
type Runner interface {
	Run(ctx context.Context, cmd string, args []string, stdin string) Result
}

// ExecRunner shells out via os/exec.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, cmd string, args []string, stdin string) Result {
	start := time.Now()
	c := exec.CommandContext(ctx, cmd, args...)
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	var outBuf, errBuf strings.Builder
	c.Stdout = &outBuf
	c.Stderr = &errBuf
	err := c.Run()

	r := Result{
		Cmd:      cmd,
		Args:     args,
		Stdin:    stdin,
		Stdout:   outBuf.String(),
		Stderr:   errBuf.String(),
		Duration: time.Since(start),
		Err:      err,
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		r.ExitCode = exitErr.ExitCode()
	} else if err == nil {
		r.ExitCode = 0
	} else {
		r.ExitCode = -1
	}
	return r
}

// MockRunner returns canned responses keyed by the full command line.
// Unknown commands return an error so tests fail loudly.
type MockRunner struct {
	Responses map[string]Result
	Calls     []Result
}

func NewMockRunner(responses map[string]Result) *MockRunner {
	if responses == nil {
		responses = map[string]Result{}
	}
	return &MockRunner{Responses: responses}
}

func (m *MockRunner) Run(_ context.Context, cmd string, args []string, stdin string) Result {
	key := cmd
	if len(args) > 0 {
		key = cmd + " " + strings.Join(args, " ")
	}
	r, ok := m.Responses[key]
	if !ok {
		r = Result{Cmd: cmd, Args: args, Stdin: stdin, Err: errors.New("no mock configured for: " + key), ExitCode: -1}
	} else {
		r.Cmd = cmd
		r.Args = args
		r.Stdin = stdin
	}
	m.Calls = append(m.Calls, r)
	return r
}

// DryRunner records commands but never executes them. Used to show the
// "commands that would run" preview in the UI.
type DryRunner struct {
	Injected map[string]Result
	Calls    []Result
}

func (d *DryRunner) Run(_ context.Context, cmd string, args []string, stdin string) Result {
	key := cmd
	if len(args) > 0 {
		key = cmd + " " + strings.Join(args, " ")
	}
	r := Result{Cmd: cmd, Args: args, Stdin: stdin, ExitCode: 0}
	if inj, ok := d.Injected[key]; ok {
		r = inj
		r.Cmd = cmd
		r.Args = args
		r.Stdin = stdin
	}
	d.Calls = append(d.Calls, r)
	return r
}

// Which reports whether cmd is on $PATH.
func Which(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}
