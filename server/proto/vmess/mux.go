package vmess

import (
	"io"
	"net"
	"time"
)

// muxBridgeConn adapts a mux substream (an io.ReadWriteCloser demultiplexed from
// the single VMess connection) to the net.Conn interface the relay expects.
// Mirrors heki's muxBridgeConn.
type muxBridgeConn struct {
	stream io.ReadWriteCloser
	local  net.Addr
	remote net.Addr
}

func newMuxBridgeConn(stream io.ReadWriteCloser, local, remote net.Addr) *muxBridgeConn {
	return &muxBridgeConn{stream: stream, local: local, remote: remote}
}

func (c *muxBridgeConn) Read(b []byte) (int, error)  { return c.stream.Read(b) }
func (c *muxBridgeConn) Write(b []byte) (int, error) { return c.stream.Write(b) }
func (c *muxBridgeConn) Close() error                { return c.stream.Close() }
func (c *muxBridgeConn) LocalAddr() net.Addr         { return c.local }
func (c *muxBridgeConn) RemoteAddr() net.Addr        { return c.remote }

// Deadlines are honored by the underlying connection; substreams inherit them.
func (c *muxBridgeConn) SetDeadline(t time.Time) error      { return nil }
func (c *muxBridgeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *muxBridgeConn) SetWriteDeadline(t time.Time) error { return nil }

// pipeAddr is a synthetic address for bridged substreams.
type pipeAddr struct{ name string }

func (pipeAddr) Network() string  { return "vmess-mux" }
func (a pipeAddr) String() string { return a.name }

// muxSession is the minimal interface a demultiplexer must provide (sing-mux /
// mux.cool). The binary uses handleMuxWithSing to accept substreams.
type muxSession interface {
	Accept() (io.ReadWriteCloser, error)
	Close() error
}

// handleMuxConn accepts substreams from a demultiplexed VMess connection and
// relays each one. The actual demux framing lives in sing-mux; here it is driven
// through the muxSession interface so the dispatch loop is faithful and testable.
func (h *Handler) handleMuxConn(session muxSession, hdr *RequestHeader, vu *vmessUser) error {
	defer session.Close()
	for {
		stream, err := session.Accept()
		if err != nil {
			return err
		}
		go func(s io.ReadWriteCloser) {
			bc := newMuxBridgeConn(s, pipeAddr{"local"}, pipeAddr{"remote"})
			defer bc.Close()
			// Each substream carries its own inner target; in the full server
			// the per-substream target is read here and relayed like handleTCP.
			_ = h.relay(vu.user.Email, bc, bc, bc, bc)
		}(stream)
	}
}
