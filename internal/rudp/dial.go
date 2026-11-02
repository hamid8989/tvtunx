package rudp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

func randConv() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	v := binary.BigEndian.Uint32(b[:])
	if v == 0 {
		v = 1
	}
	return v
}

// Dial opens a reliable-UDP connection to addr. The returned *Conn is a net.Conn.
func Dial(addr string, cfg Config) (*Conn, error) {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	sock, err := net.DialUDP("udp", nil, uaddr)
	if err != nil {
		return nil, err
	}
	if cfg.Conv == 0 {
		cfg.Conv = randConv()
	}
	psk := cfg.PSK
	c := newConn(cfg, cfg.Conv, func(b []byte) error { _, e := sock.Write(obfuscate(psk, b)); return e })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := sock.Read(buf)
			if err != nil {
				c.Close()
				return
			}
			body := deobfuscate(psk, buf[:n])
			if body == nil {
				continue
			}
			pkt := append([]byte(nil), body...)
			select {
			case c.inbox <- pkt:
			case <-c.done:
				return
			}
		}
	}()
	go func() { <-c.done; sock.Close() }()
	return c, nil
}

// Listener accepts reliable-UDP connections on one UDP socket, demultiplexing by
// remote address (one Conn per peer).
type Listener struct {
	sock   *net.UDPConn
	cfg    Config
	accept chan *Conn

	mu     sync.Mutex
	conns  map[string]*Conn
	closed chan struct{}
	once   sync.Once
}

// Listen binds a UDP socket and returns a Listener.
func Listen(addr string, cfg Config) (*Listener, error) {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	sock, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return nil, err
	}
	l := &Listener{
		sock:   sock,
		cfg:    cfg,
		accept: make(chan *Conn, 16),
		conns:  make(map[string]*Conn),
		closed: make(chan struct{}),
	}
	go l.readLoop()
	return l, nil
}

func (l *Listener) readLoop() {
	psk := l.cfg.PSK
	buf := make([]byte, 65535)
	for {
		n, raddr, err := l.sock.ReadFromUDP(buf)
		if err != nil {
			return
		}
		body := deobfuscate(psk, buf[:n])
		if body == nil || len(body) < headerSize {
			continue
		}
		pkt := append([]byte(nil), body...)
		conv := binary.BigEndian.Uint32(pkt[0:4])
		key := raddr.String()

		l.mu.Lock()
		c := l.conns[key]
		if c == nil {
			cfg := l.cfg
			cfg.Conv = conv
			ra := raddr
			c = newConn(cfg, conv, func(b []byte) error { _, e := l.sock.WriteToUDP(obfuscate(psk, b), ra); return e })
			l.conns[key] = c
			go func(k string, cc *Conn) {
				<-cc.done
				l.mu.Lock()
				if l.conns[k] == cc {
					delete(l.conns, k)
				}
				l.mu.Unlock()
			}(key, c)
			l.mu.Unlock()
			select {
			case l.accept <- c:
			case <-l.closed:
			}
		} else {
			l.mu.Unlock()
		}
		select {
		case c.inbox <- pkt:
		case <-c.done:
		}
	}
}

// Accept returns the next inbound connection.
func (l *Listener) Accept() (*Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.closed:
		return nil, errors.New("rudp: listener closed")
	}
}

func (l *Listener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.sock.Close()
}

func (l *Listener) Addr() net.Addr { return l.sock.LocalAddr() }
