package protocol

// mux.go — мультиплексирование логических стримов поверх одной сессии
// (одного *SecureConn). Формат кадра внутри уже расшифрованного потока:
//   [u32 streamID][u8 type][u16 len][payload]
// Один читатель (readLoop), запись сериализована мьютексом — это ровно
// контракт net.Conn (один параллельный читатель + один параллельный
// писатель), так что SecureConn не требует дополнительной синхронизации.
//
// ponytail: нет протокольного backpressure — при переполнении очереди
// принятых-но-невычитанных стримов новые OPEN тихо дропаются. Апгрейд —
// добавить сигнал управления потоком, если станет проблемой.

import (
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
)

const (
	frameOpen  byte = 1
	frameData  byte = 2
	frameClose byte = 3
)

// Session мультиплексирует много Stream поверх одного io.ReadWriteCloser
// (в проекте — *SecureConn).
type Session struct {
	conn     io.ReadWriteCloser
	wmu      sync.Mutex
	mu       sync.Mutex
	streams  map[uint32]*Stream
	nextID   uint32
	acceptCh chan *Stream
	closed   chan struct{}
	closeErr error
}

func NewSession(conn io.ReadWriteCloser) *Session {
	s := &Session{
		conn:     conn,
		streams:  make(map[uint32]*Stream),
		acceptCh: make(chan *Stream, 16),
		closed:   make(chan struct{}),
	}
	go s.readLoop()
	return s
}

func (s *Session) writeFrame(id uint32, typ byte, payload []byte) error {
	hdr := make([]byte, 7)
	binary.BigEndian.PutUint32(hdr[0:4], id)
	hdr[4] = typ
	binary.BigEndian.PutUint16(hdr[5:7], uint16(len(payload)))

	s.wmu.Lock()
	defer s.wmu.Unlock()
	if _, err := s.conn.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := s.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) readLoop() {
	defer s.shutdown(io.EOF)
	hdr := make([]byte, 7)
	for {
		if _, err := io.ReadFull(s.conn, hdr); err != nil {
			s.shutdown(err)
			return
		}
		id := binary.BigEndian.Uint32(hdr[0:4])
		typ := hdr[4]
		n := binary.BigEndian.Uint16(hdr[5:7])
		payload := make([]byte, n)
		if n > 0 {
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				s.shutdown(err)
				return
			}
		}

		switch typ {
		case frameOpen:
			st := s.newStream(id)
			st.openPayload = payload
			select {
			case s.acceptCh <- st:
			default:
				// backlog full -- drop; см. doc-комментарий файла про backpressure
			}
		case frameData:
			s.mu.Lock()
			st := s.streams[id]
			s.mu.Unlock()
			if st != nil {
				select {
				case st.readCh <- payload:
				case <-st.closeCh:
				}
			}
		case frameClose:
			s.mu.Lock()
			st := s.streams[id]
			delete(s.streams, id)
			s.mu.Unlock()
			if st != nil {
				st.closeOnce.Do(func() { close(st.closeCh) })
			}
		}
	}
}

func (s *Session) newStream(id uint32) *Stream {
	st := &Stream{
		id:      id,
		session: s,
		readCh:  make(chan []byte, 64),
		closeCh: make(chan struct{}),
	}
	s.mu.Lock()
	s.streams[id] = st
	s.mu.Unlock()
	return st
}

// Open (клиентская сторона) открывает новый логический стрим; payload —
// содержимое OPEN-кадра (в проекте — закодированный адрес цели, см.
// socks.EncodeAddr).
func (s *Session) Open(payload []byte) (*Stream, error) {
	id := atomic.AddUint32(&s.nextID, 1)
	st := s.newStream(id)
	if err := s.writeFrame(id, frameOpen, payload); err != nil {
		return nil, err
	}
	return st, nil
}

// Accept (серверная сторона) блокируется до следующего открытого клиентом
// стрима и возвращает его вместе с OPEN-payload (адрес цели — декодирует
// вызывающий код через socks.ReadAddr).
func (s *Session) Accept() (*Stream, []byte, error) {
	select {
	case st := <-s.acceptCh:
		return st, st.openPayload, nil
	case <-s.closed:
		return nil, nil, s.closeErr
	}
}

func (s *Session) shutdown(err error) {
	s.mu.Lock()
	select {
	case <-s.closed:
		s.mu.Unlock()
		return
	default:
	}
	s.closeErr = err
	close(s.closed)
	for _, st := range s.streams {
		st.closeOnce.Do(func() { close(st.closeCh) })
	}
	s.mu.Unlock()
}

// Stream — один логический канал внутри Session; реализует
// io.ReadWriteCloser.
type Stream struct {
	id          uint32
	session     *Session
	openPayload []byte
	readCh      chan []byte
	readBuf     []byte
	closeCh     chan struct{}
	closeOnce   sync.Once
}

func (st *Stream) Write(p []byte) (int, error) {
	if err := st.session.writeFrame(st.id, frameData, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (st *Stream) Read(p []byte) (int, error) {
	if len(st.readBuf) == 0 {
		select {
		case b, ok := <-st.readCh:
			if !ok {
				return 0, io.EOF
			}
			st.readBuf = b
		case <-st.closeCh:
			return 0, io.EOF
		}
	}
	n := copy(p, st.readBuf)
	st.readBuf = st.readBuf[n:]
	return n, nil
}

func (st *Stream) Close() error {
	st.session.mu.Lock()
	delete(st.session.streams, st.id)
	st.session.mu.Unlock()
	st.closeOnce.Do(func() { close(st.closeCh) })
	return st.session.writeFrame(st.id, frameClose, nil)
}
