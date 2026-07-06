package protocol

// mux.go — мультиплексирование логических стримов поверх одной сессии
// (одного *SecureConn). Формат кадра внутри уже расшифрованного потока:
//   [u32 streamID][u8 type][u16 len][payload]
// Один читатель (readLoop), запись сериализована мьютексом — это ровно
// контракт net.Conn (один параллельный читатель + один параллельный
// писатель), так что SecureConn не требует дополнительной синхронизации.
//
// Два разных сигнала завершения стрима, и это принципиально:
//   - удалённый CLOSE (пришёл кадр от собеседника) закрывает readCh —
//     ТОЛЬКО readLoop когда-либо закрывает readCh, и делает это строго
//     последовательно со своими же send'ами в тот же канал (единственная
//     горутина, не может слать и закрывать одновременно сама с собой) —
//     поэтому уже забуференные-но-непрочитанные данные корректно
//     дочитываются перед EOF (гарантия Go: закрытый буферизованный канал
//     сначала отдаёт всё, что в нём есть, потом уже сигналит закрытие).
//   - локальный Close() (сам код-потребитель решил бросить стрим) сигналит
//     через ОТДЕЛЬНЫЙ abandonCh, а не через readCh — так Close() никогда
//     не участвует в закрытии канала, которым владеет readLoop, и гонки
//     между «есть данные» и «удалённо закрыли» просто не существует.
//
// Более ранняя версия использовала один общий closeCh на оба случая —
// Read() гонял select{readCh, closeCh}, и если оба были готовы одновременно
// (данные уже пришли, и тут же прилетел CLOSE), Go выбирает ветку
// псевдослучайно: примерно в половине случаев терялся последний
// буферизованный кусок. Поймано вручную на реальном трафике (HTTP-ответ +
// немедленное закрытие соединения источником), не юнит-тестами и не
// -race — это состояние гонки в логике выбора, а не гонка по памяти.
//
// ponytail: нет протокольного backpressure — при переполнении очереди
// принятых-но-невычитанных стримов новые OPEN тихо дропаются (см.
// frameOpen в readLoop: стрим НЕ регистрируется в s.streams, если не
// поместился в acceptCh — иначе оставшийся в карте, но никем не
// вычитываемый стрим рано или поздно забивает свой readCh, а readLoop
// вечно блокируется, пытаясь доставить в него следующий DATA-кадр,
// останавливая тем самым всю сессию, а не только этот один запрос).
// Апгрейд — добавить сигнал управления потоком, если станет проблемой.

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

// maxFramePayload — payload-длина кадра кодируется u16, больше физически
// не влезет; Stream.Write режет более крупные Write-вызовы на несколько
// кадров вместо того, чтобы молча обрезать длину и рассинхронизировать
// поток для следующего читателя.
const maxFramePayload = 65535

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
			st := s.buildStream(id)
			st.openPayload = payload
			select {
			case s.acceptCh <- st:
				s.registerStream(st) // регистрируем, только когда реально принят в очередь
			default:
				// backlog full -- дропаем и НЕ регистрируем: последующий DATA/CLOSE
				// для этого id найдёт nil в s.streams и будет тихо проигнорирован,
				// вместо того чтобы копиться в readCh брошенного стрима и в итоге
				// заблокировать этот select навечно (см. doc-комментарий файла)
			}
		case frameData:
			s.mu.Lock()
			st := s.streams[id]
			s.mu.Unlock()
			if st != nil {
				// readCh закрывает только readLoop (эта же горутина, ниже) —
				// поэтому send здесь никогда не гонится с закрытием канала.
				select {
				case st.readCh <- payload:
				case <-st.abandonCh:
					// стрим брошен локально -- не пытаться доставить дальше
				}
			}
		case frameClose:
			s.mu.Lock()
			st := s.streams[id]
			delete(s.streams, id)
			s.mu.Unlock()
			if st != nil {
				st.closeReadCh()
			}
		}
	}
}

// buildStream строит Stream, но НЕ регистрирует его в s.streams — вызывающий
// решает, регистрировать ли (см. registerStream), в зависимости от того,
// действительно ли стрим кому-то достался (см. frameOpen выше).
func (s *Session) buildStream(id uint32) *Stream {
	return &Stream{
		id:        id,
		session:   s,
		readCh:    make(chan []byte, 64),
		abandonCh: make(chan struct{}),
	}
}

func (s *Session) registerStream(st *Stream) {
	s.mu.Lock()
	s.streams[st.id] = st
	s.mu.Unlock()
}

// Open (клиентская сторона) открывает новый логический стрим; payload —
// содержимое OPEN-кадра (в проекте — закодированный адрес цели, см.
// socks.EncodeAddr).
func (s *Session) Open(payload []byte) (*Stream, error) {
	id := atomic.AddUint32(&s.nextID, 1)
	st := s.buildStream(id)
	s.registerStream(st) // сторона-инициатор не подвержена переполнению acceptCh
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
		st.closeReadCh() // безопасно: shutdown вызывается только из readLoop
	}
	s.mu.Unlock()
}

// Stream — один логический канал внутри Session; реализует
// io.ReadWriteCloser.
type Stream struct {
	id          uint32
	session     *Session
	openPayload []byte

	readCh          chan []byte
	readChCloseOnce sync.Once // readLoop закрывает readCh не более раза
	readBuf         []byte

	abandonCh   chan struct{} // локальный Close(): "больше не читаю", см. doc файла
	abandonOnce sync.Once
}

// closeReadCh закрывает readCh при удалённом CLOSE или при остановке сессии.
// Вызывается ИСКЛЮЧИТЕЛЬНО из горутины readLoop (единственный писатель в
// readCh), поэтому конкурентных close/send с этим же каналом не бывает.
func (st *Stream) closeReadCh() {
	st.readChCloseOnce.Do(func() { close(st.readCh) })
}

func (st *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxFramePayload {
			chunk = p[:maxFramePayload]
		}
		if err := st.session.writeFrame(st.id, frameData, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (st *Stream) Read(p []byte) (int, error) {
	if len(st.readBuf) == 0 {
		select {
		case b, ok := <-st.readCh:
			if !ok {
				return 0, io.EOF
			}
			st.readBuf = b
		case <-st.abandonCh:
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
	st.abandonOnce.Do(func() { close(st.abandonCh) })
	return st.session.writeFrame(st.id, frameClose, nil)
}
