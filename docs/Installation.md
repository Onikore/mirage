# Установка и Развертывание Mirage

Mirage состоит из одного бинарного файла, который может работать как в режиме `server`, так и в режиме `client`.

## 1. Автоматическая установка (Рекомендуется для Linux-серверов)
На чистой Ubuntu/Debian/CentOS машине достаточно выполнить один bash-скрипт. Вам потребуются права `root`.

```bash
bash <(curl -sL https://raw.githubusercontent.com/Onikore/mirage/main/install.sh)
```

**Что делает скрипт:**
1. Скачивает и устанавливает `golang` (если его нет).
2. Компилирует Mirage и копирует его в `/usr/local/bin/mirage`.
3. Генерирует криптографические ключи и складывает их в `/etc/mirage/`.
4. Создает systemd-службу `mirage.service` с оптимальными настройками.
5. Запускает службу и выводит на экран готовые ключи для настройки вашего клиента.

## 2. Ручная компиляция (Для любых ОС)

Если вы хотите собрать Mirage самостоятельно (например, для Windows, macOS или роутера):

### Требования:
- Установленный **Go 1.20** или новее.

### Сборка:
```bash
git clone https://github.com/Onikore/mirage.git
cd mirage

# Для Linux / macOS / Роутеров:
CGO_ENABLED=0 go build -o mirage ./cmd/mirage

# Для Windows (создаст mirage.exe):
# На Windows GUI встроен, поэтому CGO_ENABLED отключать не обязательно,
# но если нужна только консольная версия, можно сделать так:
go build -o mirage.exe ./cmd/mirage
```

## 3. Генерация ключей вручную

Для защиты соединения Mirage использует асимметричную криптографию (публичные и приватные ключи) и симметричный PSK.

Сгенерировать связку можно встроенной командой:
```bash
./mirage keygen
```

Вывод будет выглядеть примерно так:
```text
server_priv: 7ab54e714a...
server_pub:  6ee72a2ff0...
psk:         3574dcc22b...
```
- **`server_priv`** — Приватный ключ. Хранится **ТОЛЬКО** на сервере.
- **`server_pub`** — Публичный ключ. Нужен вашему клиенту, чтобы найти сервер.
- **`psk`** — Общий пароль. Должен быть и на сервере, и на клиенте.

## 4. Настройка Systemd (Если вы ставили вручную)

Если вы хотите, чтобы Mirage работал в фоне на Linux, создайте файл `/etc/systemd/system/mirage.service`:

```ini
[Unit]
Description=Mirage Reality Proxy Server
After=network.target

[Service]
# Не забудьте подставить ваши ключи!
ExecStart=/usr/local/bin/mirage server -listen :8443 -priv ВАШ_PRIV -psk ВАШ_PSK -dest www.google.com:443 -quic
Restart=always
User=root
# Снимаем ограничения на количество открытых соединений
LimitNOFILE=512000

[Install]
WantedBy=multi-user.target
```

Затем выполните:
```bash
systemctl daemon-reload
systemctl enable mirage
systemctl start mirage
```

Логи можно смотреть командой: `journalctl -u mirage -f`
