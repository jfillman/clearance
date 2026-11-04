package gate

import (
	"errors"
	"sync"
)

// MaxWaiters caps the watches open at once (GET /v1/clearances/{id}/wait callers): past it Watch refuses, and the
// route answers 503, so long polls cannot pile up without bound.
const MaxWaiters = 512

// ErrTooManyWaiters is Watch's refusal past MaxWaiters.
var ErrTooManyWaiters = errors.New("gate: too many waiters")

// Notifier tells waiters that a change was written. The gate is the core's one writer (one operation at a time,
// under its lock), so a notification after each commit is every write: nothing polls the database to find out.
// The zero value is ready to use.
type Notifier struct {
	mu    sync.Mutex
	waits map[string]*watch
	n     int
}

type watch struct {
	ch   chan struct{}
	refs int
}

// Watch returns a channel closed at the next commit that writes change id (its row or its token), and a cancel
// that must be called when the caller stops waiting. Watch before reading the state you compare against, so a
// write between the read and the wait is not missed.
func (n *Notifier) Watch(id string) (<-chan struct{}, func(), error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.n >= MaxWaiters {
		return nil, nil, ErrTooManyWaiters
	}
	if n.waits == nil {
		n.waits = map[string]*watch{}
	}
	w := n.waits[id]
	if w == nil {
		w = &watch{ch: make(chan struct{})}
		n.waits[id] = w
	}
	w.refs++
	n.n++
	var once sync.Once
	return w.ch, func() {
		once.Do(func() {
			n.mu.Lock()
			defer n.mu.Unlock()
			n.n--
			w.refs--
			if w.refs == 0 && n.waits[id] == w {
				delete(n.waits, id)
			}
		})
	}, nil
}

// Waiting is the number of watches open.
func (n *Notifier) Waiting() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.n
}

// notify wakes the watchers of ids. A woken watcher calls Watch again to wait for the next write.
func (n *Notifier) notify(ids map[string]string) {
	if len(ids) == 0 {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for id := range ids {
		if w := n.waits[id]; w != nil {
			close(w.ch)
			delete(n.waits, id) // the cancels still count it down; a new Watch makes a new channel
		}
	}
}

// Waiting is the number of the gate's watches open.
func (s *Service) Waiting() int { return s.notify.Waiting() }
