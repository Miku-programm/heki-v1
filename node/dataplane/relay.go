package dataplane

import (
	"io"
	"net"
	"sync"
)

// copyBufPool pools 32 KiB relay buffers so each proxied connection reuses a
// buffer instead of letting io.Copy allocate a fresh one per direction.
var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// GetBuffer borrows a 32 KiB relay buffer from the pool; return it with
// PutBuffer. Used by handlers with a custom copy loop.
func GetBuffer() *[]byte { return copyBufPool.Get().(*[]byte) }

// PutBuffer returns a buffer borrowed from GetBuffer.
func PutBuffer(b *[]byte) { copyBufPool.Put(b) }

// RelayCopy copies src->dst using a pooled buffer and returns the byte count.
func RelayCopy(dst io.Writer, src io.Reader) (int64, error) {
	bp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bp)
	return io.CopyBuffer(dst, src, *bp)
}

// Relay runs a bidirectional copy between a and b with pooled buffers, closing
// both ends when either direction finishes so neither copy hangs. It returns
// (aToB, bToA) byte counts.
func Relay(a, b net.Conn) (aToB, bToA int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		aToB, _ = RelayCopy(b, a)
		a.Close()
		b.Close()
	}()
	go func() {
		defer wg.Done()
		bToA, _ = RelayCopy(a, b)
		a.Close()
		b.Close()
	}()
	wg.Wait()
	return
}
