package vmess

import (
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

// handleUDP relays UDP-over-VMess. Each AEAD body chunk carries one datagram:
// the server forwards client datagrams to the destination UDP socket and writes
// replies back as chunks. Mirrors handleUDP / udpReader / udpWriter.
func (h *Handler) handleUDP(conn net.Conn, hdr *RequestHeader, vu *vmessUser) error {
	if !h.admitIP(vu.user.Email, conn) {
		return nil
	}

	var reqMask, respMask *shakeMaskPadding
	if hdr.Option&optChunkMasking != 0 {
		reqMask = newShakeMaskPadding(hdr.BodyIV[:])
	}
	reqAEAD, err := newBodyAEAD(hdr.Security, hdr.BodyKey[:])
	if err != nil {
		return err
	}
	in := newAEADChunkReader(conn, reqAEAD, hdr.BodyIV, reqMask)

	if err := sendAEADResponseHeader(conn, hdr.BodyKey, hdr.BodyIV, hdr.ResponseVer); err != nil {
		return err
	}
	respKey, respIV := responseBodyKeyIV(hdr.BodyKey, hdr.BodyIV)
	if hdr.Option&optChunkMasking != 0 {
		respMask = newShakeMaskPadding(respIV[:])
	}
	respAEAD, err := newBodyAEAD(hdr.Security, respKey[:])
	if err != nil {
		return err
	}
	out := newAEADChunkWriter(conn, respAEAD, respIV, respMask)

	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(hdr.Address, strconv.Itoa(int(hdr.Port))))
	if err != nil {
		return err
	}
	pc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}
	defer pc.Close()

	var up, down int64

	// upstream -> client
	go func() {
		buf := make([]byte, 64*1024)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(idleTimeout))
			n, _, rerr := pc.ReadFromUDP(buf)
			if n > 0 {
				if _, werr := out.Write(buf[:n]); werr != nil {
					return
				}
				atomic.AddInt64(&down, int64(n))
			}
			if rerr != nil {
				return
			}
		}
	}()

	// client -> upstream (one chunk == one datagram)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
		pkt, rerr := in.readChunk()
		if len(pkt) > 0 {
			if _, werr := pc.Write(pkt); werr != nil {
				break
			}
			atomic.AddInt64(&up, int64(len(pkt)))
		}
		if rerr != nil {
			break
		}
	}

	h.mu.RLock()
	report := h.callbacks.ReportTraffic
	h.mu.RUnlock()
	if report != nil {
		report(vu.user.Email, atomic.LoadInt64(&up), atomic.LoadInt64(&down))
	}
	return nil
}
