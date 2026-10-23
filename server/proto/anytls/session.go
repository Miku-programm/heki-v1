package anytls

import (
	"sync"
	"time"
)

// AnyTLS multiplexes many streams over one TLS connection. sessionTracker and
// streamIdleWatchdog close a session once all its streams go idle, so pooled
// connections don't linger. Mirrors sessionTracker / streamIdleWatchdog.

// streamIdleWatchdog closes the session when no stream has been active for the
// idle timeout. The delay backs off while streams are open.
type streamIdleWatchdog struct {
	mu       sync.Mutex
	timer    *time.Timer
	idle     time.Duration
	active   int
	onExpire func()
	stopped  bool
}

func newStreamIdleWatchdog(idle time.Duration, onExpire func()) *streamIdleWatchdog {
	if idle <= 0 {
		idle = 30 * time.Second
	}
	w := &streamIdleWatchdog{idle: idle, onExpire: onExpire}
	w.timer = time.AfterFunc(idle, w.handleTimeout)
	return w
}

// nextDelayLocked returns the next idle delay: no streams open -> idle; with N
// open streams the watchdog waits longer before firing.
func (w *streamIdleWatchdog) nextDelayLocked() time.Duration {
	if w.active > 0 {
		return w.idle * time.Duration(w.active+1)
	}
	return w.idle
}

// refresh resets the idle timer (called on stream activity).
func (w *streamIdleWatchdog) refresh() {
	w.mu.Lock()
	if !w.stopped && w.timer != nil {
		w.timer.Reset(w.nextDelayLocked())
	}
	w.mu.Unlock()
}

func (w *streamIdleWatchdog) handleTimeout() {
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return
	}
	if w.active > 0 {
		w.timer.Reset(w.nextDelayLocked())
		w.mu.Unlock()
		return
	}
	w.stopped = true
	cb := w.onExpire
	w.mu.Unlock()
	if cb != nil {
		cb()
	}
}

func (w *streamIdleWatchdog) stop() {
	w.mu.Lock()
	w.stopped = true
	if w.timer != nil {
		w.timer.Stop()
	}
	w.mu.Unlock()
}

// sessionTracker counts live streams in a session and drives the watchdog.
type sessionTracker struct {
	mu       sync.Mutex
	streams  int
	watchdog *streamIdleWatchdog
}

func newSessionTracker(idle time.Duration, onIdle func()) *sessionTracker {
	t := &sessionTracker{}
	t.watchdog = newStreamIdleWatchdog(idle, onIdle)
	return t
}

// streamStart records a new stream.
func (t *sessionTracker) streamStart() {
	t.mu.Lock()
	t.streams++
	t.watchdog.mu.Lock()
	t.watchdog.active = t.streams
	t.watchdog.mu.Unlock()
	t.mu.Unlock()
	t.watchdog.refresh()
}

// streamDone records a stream closing.
func (t *sessionTracker) streamDone() {
	t.mu.Lock()
	if t.streams > 0 {
		t.streams--
	}
	t.watchdog.mu.Lock()
	t.watchdog.active = t.streams
	t.watchdog.mu.Unlock()
	t.mu.Unlock()
	t.watchdog.refresh()
}

// track runs f as a tracked stream.
func (t *sessionTracker) track(f func()) {
	t.streamStart()
	defer t.streamDone()
	f()
}

func (t *sessionTracker) stop() { t.watchdog.stop() }
