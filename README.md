# MIRAGE — скелет протокола обхода блокировок

Минимальный работающий PoC ядра: аутентифицированное рукопожатие
Noise_NKpsk0 (X25519) с анти-replay кэшем, AEAD-фреймы, SOCKS5-вход,
анти-зонд-fallback; обе половины рукопожатия замаскированы под настоящий
TLS 1.3 (client->server — под Chrome ClientHello через uTLS, server->client
— под минимальный спецификационно корректный ServerHello). Внешние
зависимости — uTLS (байт-в-байт совместимые TLS-фингерпринты браузеров) и
flynn/noise (аудированная реализация Noise Protocol Framework вместо
самодельной крипто-последовательности).

Это **скелет для проверки идеи**, не боевой инструмент. Что намеренно упрощено —
см. раздел «Что дальше».

## Сборка

```
go build -o mirage ./cmd/mirage
```

### Windows GUI

Кросс-компилируется с Linux/macOS без mingw/cgo (`github.com/lxn/walk`
оборачивает Win32 напрямую). Два разных вывода из одного и того же кода —
разные линкер-флаги под разное использование:

```bash
# mirage.exe — консольная подсистема, для запуска из cmd/PowerShell
# (keygen/server/client, видимый лог)
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o mirage.exe ./cmd/mirage

# mirage-gui.exe — windowsgui подсистема, для запуска двойным кликом
# (без мелькающей консоли позади окна)
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-H windowsgui" -o mirage-gui.exe ./cmd/mirage
```

Обе сборки — один и тот же бинарник с одними и теми же подкомандами;
разница только в том, видна ли консоль. `mirage-gui.exe` без аргументов
сразу открывает GUI (`gui` подкоманда), `mirage.exe` без GUI-флага ведёт
себя как обычный CLI.

## Запуск (локальный тест)

```
# 1. ключи
./mirage keygen
#   server_priv: <PRIV>
#   server_pub:  <PUB>
#   psk:         <PSK>

# 2. сервер (dest — реальный сайт, куда уводятся зонды)
./mirage server -listen :8443 -priv <PRIV> -psk <PSK> -dest example.com:443

# 3. клиент (локальный SOCKS5)
./mirage client -listen 127.0.0.1:1080 -server SERVER_IP:8443 -pub <PUB> -psk <PSK>

# 4. направь браузер/curl в SOCKS5
curl --socks5-hostname 127.0.0.1:1080 https://blocked.example/
```

## Что проверено (loopback)

1. Легитимный трафик проходит через туннель.
2. Клиент с неверным PSK — рукопожатие отвергается, туннель не строится.
3. Сырой HTTP-зонд на порт сервера прозрачно проксируется на `dest` —
   сервер неотличим от обычного веб-сервера.
4. Рукопожатие клиента замаскировано под TLS 1.3 ClientHello (Chrome) —
   первый байт на проводе больше не «голый» X25519.
5. Рукопожатие — Noise_NKpsk0 (flynn/noise): неверный PSK и мусорные байты
   одинаково отклоняются сервером на первом сообщении, без паники; ключи,
   выпущенные предыдущей (самодельной) версией `keygen`, остаются рабочими
   без переgen.
6. Анти-replay: повтор ранее принятого msg1 отклоняется сервером и уходит
   в тот же fallback, что и обычный зонд; мусор и неверный PSK в кэш не
   попадают (проверяется только после успешной аутентификации).
7. Rate-limit: burst=5 быстрых подключений с одного IP проходят, следующие
   уходят в тот же fallback без попытки крипто-работы; после паузы лимит
   восстанавливается.
8. Ротация ключей без остановки сервера: `-psk-file` с двумя ключами —
   старый и новый работают одновременно; после `SIGHUP` со списком из
   одного (нового) ключа старый psk-клиент отклоняется, новый продолжает
   работать — весь процесс на одном и том же PID сервера, без рестарта.
9. ServerHello теперь тоже замаскирован (см. servhello.go) — легитимный
   трафик, bad-PSK fallback и raw-probe fallback проверены заново поверх
   этой мимикрии, ведут себя как раньше.

## Как устроено

```
Браузер ──SOCKS5──> client ──[Noise_NKpsk0 handshake + AEAD frames]──> server ──> target
                                                                    │
                                                        (плохой auth) └──> dest (реальный сайт)
```

Три пакета вместо одной кучи файлов в корне:

```
cmd/mirage/            — точка входа: CLI-подкоманды + Windows GUI
internal/protocol/     — сам протокол: Noise-рукопожатие + TLS-камуфляж + AEAD-фреймы
internal/socks/        — SOCKS5-вход клиента
```

**`internal/protocol/`** (пакет `protocol`)
- `crypto.go`     — набор примитивов (X25519 + AES-256-GCM + SHA-256) и
  генерация ключей для flynn/noise
- `handshake.go`  — рукопожатие Noise_NKpsk0: forward secrecy (эфемерали),
  PSK вплетён в первое же сообщение (auth клиента + анти-зонд).
  Экспортирует `ClientHandshake`/`ServerHandshake`/`SecureConn`.
- `replay.go`     — анти-replay кэш эфемеральных pubkey клиентов (окно 2
  мин). Экспортирует `ReplayCache`/`NewReplayCache`/`ReplayWindow`.
- `camouflage.go` — упаковка/разбор client->server рукопожатия как
  мимикрированного TLS ClientHello (uTLS, Chrome-фингерпринт)
- `servhello.go`  — упаковка/разбор server->client половины как
  минимального спецификационно корректного TLS 1.3 ServerHello
- `frame.go`      — потоковый AEAD-канал (`SecureConn`, io.ReadWriteCloser)
  поверх `noise.CipherState`, хук для shaping

**`internal/socks/`** (пакет `socks`)
- `socks.go` — SOCKS5-вход (`socks.Accept`)
- `addr.go`  — кодирование целевого адреса (`socks.EncodeAddr`/`socks.ReadAddr`)

**`cmd/mirage/`** (пакет `main`)
- `main.go`        — keygen / server / client / gui; per-IP rate-limit
  (`ratelimit.go`) и набор psk с ротацией (`pskset.go`) живут здесь же —
  это чисто CLI/server-оркестрация, не часть протокола
- `ratelimit.go`   — per-IP token-bucket лимит попыток подключения
- `pskset.go`      — набор одновременно валидных psk + горячая
  перезагрузка списка по SIGHUP (ротация без остановки сервера)
- `gui_windows.go` — GUI-клиент (только Windows): поля + Connect/Disconnect
  поверх того же `runClientListener`, что и `mirage client`
- `gui_other.go`   — заглушка `cmdGUI` для не-Windows сборок
- `guiconfig.go`   — сохранение/загрузка последних введённых в GUI полей

## Что дальше (по приоритету)

1. **QUIC/HTTP3-план.** quic-go, датаграммы для UDP, стримы для TCP,
   connection migration. Salamander-обфускация QUIC-заголовка. Крупная,
   отдельная от остального работа — новый транспорт, не правка поверх
   текущего TCP-ядра.
2. **Мультиплекс.** Сейчас одно TCP-соединение на один запрос. Добавить
   stream_id в кадры, гонять все стримы по одной сессии.
3. **Chameleon shaping.** PADDING-кадры + подгонка размеров/таймингов под
   профиль реального HTTP/3-трафика. Хук уже размечен в frame.go.

ClientHello- и ServerHello-камуфляж (uTLS + см. servhello.go) и
операционная обвязка вокруг Noise-рукопожатия (rate-limit, анти-replay,
ротация psk без остановки сервера) уже сделаны — см. camouflage.go,
servhello.go, ratelimit.go, replay.go, pskset.go. `server_priv` при этом
по-прежнему один и не ротируется (для этого нужна была бы смена ключа при
живых соединениях — не делали, за пределами этой итерации). Полноценный
Reality-стиль (заимствование настоящего сертификата у `-dest` через
проксирование живого handshake) тоже не делали — нынешний ServerHello
спецификационно корректен, но статичен, не привязан к реальному TLS-сайту.

## Дисклеймер

Ещё не боевой код: QUIC/мультиплекс/shaping не сделаны, `server_priv` не
ротируется, ServerHello спецификационно корректен, но не Reality-уровня
(не заимствует сертификат у реального сайта). Само рукопожатие теперь на
полноценном Noise (flynn/noise), не самодельное, обе половины (ClientHello
и ServerHello) замаскированы под TLS 1.3, есть защита от replay msg1
(replay.go), per-IP rate-limit (ratelimit.go) и ротация psk без остановки
сервера (pskset.go) — но пп. 1-3 выше ещё не сделаны. Для реального
использования — форкать sing-box/xray и переиспользовать их обкатанные
транспорт и Reality.
