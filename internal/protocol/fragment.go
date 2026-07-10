package protocol

import (
	"math/rand"
	"net"
	"time"
)

// fragmentedConn wraps a net.Conn and aggressively fragments the first
// writes (usually the TLS ClientHello) into tiny TCP packets.
// This is highly effective against regex-based DPI systems.
type fragmentedConn struct {
	net.Conn
	bytesWritten int
	fragmentSize int
	fragmentWait time.Duration
	maxFragment  int
}

// NewFragmentedConn creates a wrapper that fragments the first maxFragment
// bytes of data written to it into chunks of fragmentSize.
func NewFragmentedConn(c net.Conn) net.Conn {
	// Typically ClientHello is around 500-1500 bytes.
	// Fragmenting the first 2000 bytes is usually enough.
	return &fragmentedConn{
		Conn:         c,
		fragmentSize: 10 + rand.Intn(10), // 10-19 bytes per chunk
		fragmentWait: time.Millisecond * 2,
		maxFragment:  2000,
	}
}

func (c *fragmentedConn) Write(b []byte) (n int, err error) {
	if c.bytesWritten >= c.maxFragment {
		// Optimization: if we already fragmented the beginning,
		// just passthrough.
		nn, err := c.Conn.Write(b)
		c.bytesWritten += nn
		return nn, err
	}

	var written int
	for written < len(b) {
		if c.bytesWritten >= c.maxFragment {
			// Write the rest normally
			nn, err := c.Conn.Write(b[written:])
			written += nn
			c.bytesWritten += nn
			return written, err
		}

		chunkSize := c.fragmentSize
		if written+chunkSize > len(b) {
			chunkSize = len(b) - written
		}

		// Write a small chunk
		nn, err := c.Conn.Write(b[written : written+chunkSize])
		written += nn
		c.bytesWritten += nn
		if err != nil {
			return written, err
		}

		// Sleep slightly to force TCP to send it as a separate packet.
		// Requires TCP_NODELAY to be set on the underlying socket (which Go does by default).
		time.Sleep(c.fragmentWait)
	}
	return written, nil
}
