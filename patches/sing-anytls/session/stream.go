package session

import (
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anytls/sing-anytls/internal/pipe"
)

// NOTE: reconstructed heki patch. heki's private ./patches/sing-anytls inserts
// an asynchronous per-stream receive queue + pump between Session.recvLoop and
// the Stream's pipe, so a slow stream reader cannot block the whole session's
// recvLoop (head-of-line-blocking fix), and makes the die-error access atomic
// (race fix). Recovered from the shipped binary via Hex-Rays decompilation of
// (*Stream).Read / runRecvPump / enqueueRecvItem / newStream. This is a
// behaviour reconstruction of that patch, not heki's exact source.

// errHolder lets the die-error be stored/loaded atomically.
type errHolder struct{ err error }

// Stream implements net.Conn
type Stream struct {
	id uint32

	sess *Session

	pipeR         *pipe.PipeReader
	pipeW         *pipe.PipeWriter
	writeDeadline pipe.PipeDeadline

	// async receive path (heki patch)
	recvQueue    chan []byte
	recvDone     chan struct{}
	recvInflight atomic.Int64
	doneOnce     sync.Once

	dieOnce sync.Once
	dieHook func()
	dieErr  atomic.Pointer[errHolder]

	reportOnce sync.Once
}

func (s *Stream) storeDieErr(err error) { s.dieErr.Store(&errHolder{err}) }

func (s *Stream) loadDieErr() error {
	if h := s.dieErr.Load(); h != nil {
		return h.err
	}
	return nil
}

// newStream initiates a Stream struct
func newStream(id uint32, sess *Session) *Stream {
	s := new(Stream)
	s.id = id
	s.sess = sess
	s.pipeR, s.pipeW = pipe.Pipe()
	s.writeDeadline = pipe.MakePipeDeadline()
	s.recvQueue = make(chan []byte, 256)
	s.recvDone = make(chan struct{})
	go s.runRecvPump()
	return s
}

// runRecvPump drains recvQueue into the pipe so Session.recvLoop never blocks on
// a slow reader. It stops on recvDone, then drains any queued items.
func (s *Stream) runRecvPump() {
	for {
		select {
		case <-s.recvDone:
			s.pipeW.CloseWithError(s.loadDieErr())
			for {
				select {
				case data := <-s.recvQueue:
					_ = data
					s.recvInflight.Add(-1)
				default:
					if s.recvInflight.Load() == 0 {
						return
					}
				}
			}
		case data := <-s.recvQueue:
			s.recvInflight.Add(-1)
			if _, err := s.pipeW.Write(data); err != nil {
				// reader gone; keep draining until recvDone
			}
		}
	}
}

// enqueueRecvItem hands a received PSH payload to the pump without blocking the
// session recvLoop. The payload is copied because the caller reuses its buffer.
func (s *Stream) enqueueRecvItem(data []byte) {
	select {
	case <-s.recvDone:
		return
	default:
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	s.recvInflight.Add(1)
	select {
	case s.recvQueue <- cp:
	case <-s.recvDone:
		s.recvInflight.Add(-1)
	}
}

func (s *Stream) signalRecvDone() {
	s.doneOnce.Do(func() { close(s.recvDone) })
}

// Read implements net.Conn
func (s *Stream) Read(b []byte) (n int, err error) {
	n, err = s.pipeR.Read(b)
	if n == 0 {
		if de := s.loadDieErr(); de != nil {
			err = de
		}
	}
	return
}

// Write implements net.Conn
func (s *Stream) Write(b []byte) (n int, err error) {
	select {
	case <-s.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if de := s.loadDieErr(); de != nil {
		return 0, de
	}
	n, err = s.sess.writeDataFrame(s.id, b)
	return
}

// Close implements net.Conn
func (s *Stream) Close() error {
	return s.closeWithError(io.ErrClosedPipe)
}

// closeLocally only closes Stream and don't notify remote peer
func (s *Stream) closeLocally() {
	var once bool
	s.dieOnce.Do(func() {
		s.storeDieErr(net.ErrClosed)
		s.signalRecvDone()
		s.pipeR.Close()
		once = true
	})
	if once {
		if s.dieHook != nil {
			s.dieHook()
			s.dieHook = nil
		}
	}
}

func (s *Stream) closeWithError(err error) error {
	var once bool
	s.dieOnce.Do(func() {
		s.storeDieErr(err)
		s.signalRecvDone()
		s.pipeR.Close()
		once = true
	})
	if once {
		err := s.sess.streamClosed(s.id)
		if s.dieHook != nil {
			s.dieHook()
			s.dieHook = nil
		}
		return err
	}
	return s.loadDieErr()
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	return s.pipeR.SetReadDeadline(t)
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Set(t)
	return nil
}

func (s *Stream) SetDeadline(t time.Time) error {
	s.SetWriteDeadline(t)
	return s.SetReadDeadline(t)
}

// LocalAddr satisfies net.Conn interface
func (s *Stream) LocalAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		LocalAddr() net.Addr
	}); ok {
		return ts.LocalAddr()
	}
	return nil
}

// RemoteAddr satisfies net.Conn interface
func (s *Stream) RemoteAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		RemoteAddr() net.Addr
	}); ok {
		return ts.RemoteAddr()
	}
	return nil
}

// HandshakeFailure should be called when Server fail to create outbound proxy
func (s *Stream) HandshakeFailure(err error) error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && err != nil && s.sess.peerVersion >= 2 {
		f := newFrame(cmdSYNACK, s.id)
		f.data = []byte(err.Error())
		if _, err := s.sess.writeControlFrame(f); err != nil {
			return err
		}
	}
	return nil
}

// HandshakeSuccess should be called when Server success to create outbound proxy
func (s *Stream) HandshakeSuccess() error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && s.sess.peerVersion >= 2 {
		if _, err := s.sess.writeControlFrame(newFrame(cmdSYNACK, s.id)); err != nil {
			return err
		}
	}
	return nil
}
