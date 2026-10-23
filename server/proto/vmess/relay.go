package vmess

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"heki/node/dataplane"
)

// idleTimeout refreshes the connection deadline during relay (copyBufferWithRefresh).
const idleTimeout = 5 * time.Minute

// handleTCP relays a decrypted VMess TCP request to its destination: it wraps the
// client stream in the request body AEAD, sends the response header, wraps the
// reply in the response body AEAD, dials upstream, and copies both directions
// under the user's limiter with traffic/alive-IP accounting.
func (h *Handler) handleTCP(conn net.Conn, hdr *RequestHeader, vu *vmessUser) error {
	if !h.admitIP(vu.user.Email, conn) {
		return nil
	}

	var mask *shakeMaskPadding
	if hdr.Option&optChunkMasking != 0 {
		mask = newShakeMaskPadding(hdr.BodyIV[:])
	}
	reqAEAD, err := newBodyAEAD(hdr.Security, hdr.BodyKey[:])
	if err != nil {
		return err
	}
	clientReader := newAEADChunkReader(conn, reqAEAD, hdr.BodyIV, mask)

	// response path
	if err := sendAEADResponseHeader(conn, hdr.BodyKey, hdr.BodyIV, hdr.ResponseVer); err != nil {
		return err
	}
	respKey, respIV := responseBodyKeyIV(hdr.BodyKey, hdr.BodyIV)
	var respMask *shakeMaskPadding
	if hdr.Option&optChunkMasking != 0 {
		respMask = newShakeMaskPadding(respIV[:])
	}
	respAEAD, err := newBodyAEAD(hdr.Security, respKey[:])
	if err != nil {
		return err
	}
	clientWriter := newAEADChunkWriter(conn, respAEAD, respIV, respMask)

	upstream, err := dataplane.DialOrDirect(context.Background(), h.dialer, dataplane.Meta{
		UserEmail: vu.user.Email, Protocol: "vmess", Network: "tcp",
		ClientIP: dataplane.RemoteIP(conn.RemoteAddr()), IngressLocalIP: dataplane.HostIP(conn.LocalAddr().String()),
	}, hdr.Address, int(hdr.Port))
	if err != nil {
		return err
	}
	defer upstream.Close()

	return h.relay(vu.user.Email, conn, upstream, clientReader, clientWriter)
}

// relay copies client<->upstream and reports byte counts. clientReader yields
// decrypted client bytes; clientWriter encrypts server bytes back to the client.
func (h *Handler) relay(email string, conn, upstream net.Conn, cr io.Reader, cw io.Writer) error {
	var up, down int64
	var wg sync.WaitGroup
	wg.Add(2)

	go func() { // client -> upstream
		defer wg.Done()
		n := copyBufferWithRefresh(upstream, cr, conn)
		atomic.AddInt64(&up, n)
		if tc, ok := upstream.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	go func() { // upstream -> client
		defer wg.Done()
		n := copyBufferWithRefresh(cw, upstream, conn)
		atomic.AddInt64(&down, n)
	}()
	wg.Wait()

	h.mu.RLock()
	report := h.callbacks.ReportTraffic
	h.mu.RUnlock()
	if report != nil {
		report(email, atomic.LoadInt64(&up), atomic.LoadInt64(&down))
	}
	return nil
}

// copyBufferWithRefresh copies src->dst, refreshing deadlineConn's read/write
// deadline on progress so idle connections eventually time out.
func copyBufferWithRefresh(dst io.Writer, src io.Reader, deadlineConn net.Conn) int64 {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		if deadlineConn != nil {
			_ = deadlineConn.SetDeadline(time.Now().Add(idleTimeout))
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			total += int64(nw)
			if ew != nil {
				return total
			}
		}
		if er != nil {
			return total
		}
	}
}
