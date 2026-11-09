package collector

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Message is one SQS message.
type Message struct {
	ID, Handle, Body string
}

// Queue is the SQS queue the EventBridge rules deliver to (feeds.SQS). Receive long-polls.
type Queue interface {
	Receive(ctx context.Context) ([]Message, error)
	Delete(ctx context.Context, handle string) error
}

// Drainer reads the queue into the collector. Consumption is at-least-once: a message is deleted only after its change
// was posted (the Item's ack), a message that does not parse is left (the queue's redrive policy sends it to a
// dead-letter queue after its receive count), and a redelivery is absorbed by the reconciler or, after a restart, by
// the core's de-duplication on the event id.
type Drainer struct {
	Q      Queue
	Col    *Collector
	Health *Health
	Batch  int // receives per Drain (default 10)
	Log    *slog.Logger
}

func (d *Drainer) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}

// Drain receives until the queue is empty or Batch receives were made, and returns how many messages it took in.
func (d *Drainer) Drain(ctx context.Context) (int, error) {
	n := 0
	var bad []string
	for i := 0; i < orN(d.Batch, 10); i++ {
		msgs, err := d.Q.Receive(ctx)
		if err != nil {
			return n, err
		}
		if d.Health != nil {
			d.Health.Drained()
		}
		if len(msgs) == 0 {
			break
		}
		for _, m := range msgs {
			it, err := ParseMessage([]byte(m.Body), d.Col.now())
			if err != nil {
				bad = append(bad, m.ID+": "+err.Error())
				d.Col.count(func(s *Stats) { s.Errors++ })
				continue // left on the queue: redriven to the dead-letter queue
			}
			h := m.Handle
			it.Acks = []func(){func() {
				if err := d.Q.Delete(context.WithoutCancel(ctx), h); err != nil {
					d.log().Warn("deleting a processed message failed; it will be redelivered and absorbed", "id", m.ID, "err", err.Error())
				}
			}}
			if err := d.Col.Ingest(it); err != nil {
				bad = append(bad, m.ID+": "+err.Error())
				continue
			}
			n++
		}
	}
	if len(bad) > 0 {
		return n, errors.New("messages left on the queue: " + strings.Join(bad, "; "))
	}
	return n, nil
}

func orN(n, d int) int {
	if n > 0 {
		return n
	}
	return d
}

// Task is one thing the collector does on a schedule.
type Task struct {
	Name  string
	Every time.Duration
	Fn    func(ctx context.Context) error
	next  time.Time
}

// Runner runs tasks when they are due. A task that fails is logged and tried again at its next time; one task's
// failure never stops another.
type Runner struct {
	Tasks []*Task
	Now   func() time.Time
	Log   *slog.Logger

	mu sync.Mutex
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Tick runs every task that is due, in order, and returns their errors.
func (r *Runner) Tick(ctx context.Context) []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var errs []error
	for _, t := range r.Tasks {
		if r.now().Before(t.next) {
			continue
		}
		err := t.Fn(ctx)
		t.next = r.now().Add(t.Every)
		if err != nil {
			errs = append(errs, errors.New(t.Name+": "+err.Error()))
			if r.Log != nil {
				r.Log.Warn("task failed", "task", t.Name, "err", err.Error())
			}
		}
	}
	return errs
}

// Run ticks every poll until ctx is done.
func (r *Runner) Run(ctx context.Context, poll time.Duration) {
	tk := time.NewTicker(poll)
	defer tk.Stop()
	for {
		r.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
	}
}
