# Mirage 🛡️

**Mirage** — прокси-туннель, устойчивый к системам глубокого анализа трафика (DPI), для обхода интернет-цензуры (GFW, ТСПУ и подобные). Трафик маскируется под обычные TLS-подключения к настоящим сайтам (Reality-маскировка), а всё реальное шифрование данных обеспечивает протокол **Noise** (`Noise_NKpsk0`, аудированная реализация `flynn/noise`) — с настоящей прямой секретностью (Perfect Forward Secrecy).

Это **исследовательский proof-of-concept**, не готовый к бою инструмент промышленного качества — см. «Известные ограничения» ниже, а также `DEPLOY.md` и `docs/Architecture.md`.

## 📖 Документация

- 🏗️ **[Архитектура и протокол (docs/Architecture.md)](docs/Architecture.md)** — как устроены Noise-рукопожатие, Reality-маскировка, TCP-фрагментация, мультиплексирование, TCP/QUIC-транспорты.
- 🚀 **[Установка (docs/Installation.md)](docs/Installation.md)** — `install.sh`, ручная сборка, systemd.
- 💻 **[Использование и CLI-флаги (docs/Usage.md)](docs/Usage.md)** — все аргументы, ротация ключей, API статистики.
- 🔌 **[Интеграция с Shadowsocks / SIP003 (docs/Integration_SIP003.md)](docs/Integration_SIP003.md)** — режим плагина для v2rayN, shadowsocks-rust и т.п.
- 📋 **[DEPLOY.md](DEPLOY.md)** — практическая инструкция «кто, на какой ОС, что запускает»: сервер на Ubuntu/Windows, клиент на Ubuntu/Windows (CLI и GUI).

## ⚡ Быстрый старт (Linux-сервер)

```bash
bash <(curl -sL https://raw.githubusercontent.com/Onikore/mirage/master/install.sh)
```

Скрипт клонирует репозиторий, при необходимости ставит Go 1.25+, собирает проект, генерирует ключи и запускает `mirage.service`. Требует `root`.

Клиент (CLI или GUI, Windows/Linux) — см. `DEPLOY.md`.

## Известные ограничения

- `server_priv` не ротируется на живых соединениях (в отличие от `psk`,
  который можно менять через `-psk-file` + `SIGHUP` без даунтайма).
- QUIC-транспорт, SIP003-плагин, TCP-фрагментация и Stats API — новые,
  без автотестов; проверялись вручную.
- SOCKS5 UDP ASSOCIATE не поддерживается (только `CONNECT`) — см.
  `docs/Architecture.md`.
- Reality ServerHello валиден по форме и несёт настоящий сертификат
  `-dest`, но это не полноценная эмуляция живого TLS-сайта дальше
  хендшейка.
- `-sni` на клиенте обязан совпадать с `-dest` на сервере — это не
  косметика, а требование механизма (сервер в буквальном смысле
  пересылает ClientHello с этим SNI на `-dest`).

## Лицензия

MIT License
