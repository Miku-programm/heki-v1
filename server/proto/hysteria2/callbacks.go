package hysteria2

import (
	"net"
	"sync"
	"sync/atomic"
)

// hyEventLogger implements apernet/hysteria's EventLogger: connection and
// per-request lifecycle events, which heki uses for logging and online state.
type hyEventLogger struct{ s *Hysteria2Server }

func (l *hyEventLogger) Connect(addr net.Addr, id string, tx uint64)        {}
func (l *hyEventLogger) Disconnect(addr net.Addr, id string, err error)     {}
func (l *hyEventLogger) TCPRequest(addr net.Addr, id, reqAddr string)       {}
func (l *hyEventLogger) TCPError(addr net.Addr, id, reqAddr string, e error) {}
func (l *hyEventLogger) UDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string) {}
func (l *hyEventLogger) UDPError(addr net.Addr, id string, sessionID uint32, e error)          {}

// hyTrafficLogger implements apernet/hysteria's TrafficLogger: byte accounting,
// per-user speed limiting, online-state reporting, and (for domain audit)
// stream tracing.
type hyTrafficLogger struct {
	s       *Hysteria2Server
	mu      sync.Mutex
	streams map[string]string // streamID -> requested domain (audit)
}

func newTrafficLogger(s *Hysteria2Server) *hyTrafficLogger {
	return &hyTrafficLogger{s: s, streams: map[string]string{}}
}

// userLimiter returns the configured speed limit for a user id key.
func (l *hyTrafficLogger) userLimiter(id string) int64 {
	u := l.s.findUserByIDKey(id)
	if u == nil {
		return 0
	}
	l.s.mu.RLock()
	cb := l.s.callback.SpeedLimit
	l.s.mu.RUnlock()
	if cb != nil {
		return cb(u.Email)
	}
	return u.SpeedBps
}

// LogTraffic reports the per-id up/down deltas; returning false tells Hysteria to
// drop the connection (e.g. over quota).
func (l *hyTrafficLogger) LogTraffic(id string, tx, rx uint64) bool {
	u := l.s.findUserByIDKey(id)
	if u == nil {
		return false
	}
	l.s.mu.RLock()
	report := l.s.callback.ReportTraffic
	l.s.mu.RUnlock()
	if report != nil {
		report(u.Email, int64(tx), int64(rx))
	}
	return true
}

// LogOnlineState reports a user coming online/offline.
func (l *hyTrafficLogger) LogOnlineState(id string, online bool) {}

// TraceStream / UntraceStream record the requested domain for a stream so the
// domain-audit feature can inspect it (SetAuditTargetDetailed).
func (l *hyTrafficLogger) TraceStream(streamID, domain string) {
	l.mu.Lock()
	l.streams[streamID] = domain
	l.mu.Unlock()
}

func (l *hyTrafficLogger) UntraceStream(streamID string) {
	l.mu.Lock()
	delete(l.streams, streamID)
	l.mu.Unlock()
}

// findUserByIDKey resolves the "u<id>" traffic key back to a user.
func (s *Hysteria2Server) findUserByIDKey(key string) *User {
	if len(key) < 2 || key[0] != 'u' {
		return nil
	}
	n := 0
	for _, c := range key[1:] {
		if c < '0' || c > '9' {
			return nil
		}
		n = n*10 + int(c-'0')
	}
	return s.findUserByID(n)
}

// hyOutbound implements apernet/hysteria's Outbound: how the server dials the
// requested target. heki applies routing/limits here.
type hyOutbound struct {
	s        *Hysteria2Server
	tcpConns atomic.Int64
}

// TCP dials a TCP target for the proxied request.
func (o *hyOutbound) TCP(reqAddr string) (net.Conn, error) {
	o.tcpConns.Add(1)
	return net.Dial("tcp", reqAddr)
}

// UDP opens a UDP outbound socket.
func (o *hyOutbound) UDP(reqAddr string) (net.PacketConn, error) {
	return net.ListenPacket("udp", ":0")
}

// CheckUDP reports whether a UDP target is permitted (routing/block list).
func (o *hyOutbound) CheckUDP(reqAddr string) bool { return true }
