package vmess

import (
	"io"
	"net"
)

// peekReader records every byte read from the underlying connection so that, on
// an authentication failure, the exact bytes already consumed can be replayed
// to the fallback (real-site) target — the transparent-fallback behavior the
// original uses to resist active probing.
type peekReader struct {
	r   io.Reader
	log []byte
}

func newPeekReader(r io.Reader) *peekReader { return &peekReader{r: r} }

func (p *peekReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.log = append(p.log, b[:n]...)
	}
	return n, err
}

// restored returns a net.Conn that first replays the bytes consumed during
// authentication, then continues from the live connection.
func (p *peekReader) restored(conn net.Conn) net.Conn {
	return &replayConn{Conn: conn, head: p.log}
}

type replayConn struct {
	net.Conn
	head []byte
	off  int
}

func (c *replayConn) Read(b []byte) (int, error) {
	if c.off < len(c.head) {
		n := copy(b, c.head[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(b)
}
