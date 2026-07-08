package protocol

// servhello.go — обёртка server->client половины рукопожатия (msg2) в
// минимальный, спецификационно корректный TLS 1.3 ServerHello + одна
// продолжающая запись, чтобы обе половины хендшейка выглядели как TLS,
// а не только client->server (см. camouflage.go).
//
// В отличие от ClientHello, ServerHello не обязан байт-в-байт совпадать с
// конкретной реализацией (JA3/JA4-подобный фингерпринтинг бьёт по
// клиентам, не по серверам) — важна только валидная форма: настоящий
// TLS 1.3 сервер в ответ на X25519 ClientHello посылает key_share со своим
// эфемерным pubkey и обязан эхом вернуть session_id клиента.
//
// Наш server-side X25519 ephemeral pubkey (esPub) едет в key_share, как и
// раньше. AEAD-тег (tag2, 16 байт) едет отдельной "продолжающей" записью с
// content-type 0x17 (application_data) — так реальный TLS 1.3 сервер шлёт
// EncryptedExtensions/Certificate/Finished сразу вслед за ServerHello;
// снаружи (без ключей) это неотличимо от непрозрачного шифротекста любой
// длины.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

const (
	extSupportedVersions  = 0x002b
	extKeyShare           = 0x0033
	groupX25519           = 0x001d
	cipherAES128GCMSHA256 = 0x1301
)

func buildMimicServerHello(sessionIDEcho, esPub, tag2 []byte) ([]byte, error) {
	if len(esPub) != 32 || len(tag2) != 16 {
		return nil, errors.New("mirage: buildMimicServerHello: esPub must be 32 bytes, tag2 must be 16 bytes")
	}
	if len(sessionIDEcho) > 32 {
		return nil, errors.New("mirage: buildMimicServerHello: sessionIDEcho too long")
	}

	var body []byte
	body = append(body, 0x03, 0x03) // legacy_version (compat)
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	body = append(body, random...)
	body = append(body, byte(len(sessionIDEcho)))
	body = append(body, sessionIDEcho...)
	body = append(body, cipherAES128GCMSHA256>>8, cipherAES128GCMSHA256&0xff)
	body = append(body, 0x00) // legacy_compression_method

	var exts []byte
	exts = append(exts, extSupportedVersions>>8, extSupportedVersions&0xff)
	exts = append(exts, 0x00, 0x02)
	exts = append(exts, 0x03, 0x04) // selected_version = TLS 1.3
	ksBody := []byte{groupX25519 >> 8, groupX25519 & 0xff, 0x00, 0x20}
	ksBody = append(ksBody, esPub...)
	exts = append(exts, extKeyShare>>8, extKeyShare&0xff)
	exts = append(exts, byte(len(ksBody)>>8), byte(len(ksBody)))
	exts = append(exts, ksBody...)

	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, 0x02) // ServerHello
	l := len(body)
	handshake = append(handshake, byte(l>>16), byte(l>>8), byte(l))
	handshake = append(handshake, body...)

	hello := make([]byte, 0, 5+len(handshake))
	hello = append(hello, 0x16, 0x03, 0x03)
	hello = append(hello, byte(len(handshake)>>8), byte(len(handshake)))
	hello = append(hello, handshake...)

	cont := make([]byte, 5+len(tag2))
	cont[0] = 0x17 // application_data — как реальный TLS1.3 шифрует EncryptedExtensions+
	cont[1], cont[2] = 0x03, 0x03
	binary.BigEndian.PutUint16(cont[3:5], uint16(len(tag2)))
	copy(cont[5:], tag2)

	return append(hello, cont...), nil
}

// parseMimicServerHello читает мимикрированный ServerHello + продолжающую
// запись из r и возвращает esPub/tag2 — сырой 48-байтовый Noise-msg2
// собирается вызывающим кодом как esPub||tag2.
func parseMimicServerHello(r io.Reader) (esPub, tag2 []byte, err error) {
	esPub, err = readServerHelloRecord(r)
	if err != nil {
		return nil, nil, err
	}
	tag2, err = readContinuationRecord(r)
	if err != nil {
		return nil, nil, err
	}
	return esPub, tag2, nil
}

func readServerHelloRecord(r io.Reader) (esPub []byte, err error) {
	hdr := make([]byte, 5)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 0x16 {
		return nil, errors.New("mirage: not a handshake record")
	}
	n := binary.BigEndian.Uint16(hdr[3:5])
	if n == 0 || n > maxMimicHelloLen {
		return nil, errors.New("mirage: implausible server hello length")
	}
	hs := make([]byte, n)
	if _, err = io.ReadFull(r, hs); err != nil {
		return nil, err
	}
	if len(hs) < 4 || hs[0] != 0x02 {
		return nil, errors.New("mirage: not a ServerHello")
	}
	body := hs[4:]

	pos := 2 + 32 // legacy_version + random
	if len(body) < pos+1 {
		return nil, errors.New("mirage: truncated server hello")
	}
	sidLen := int(body[pos])
	pos++
	pos += sidLen // session_id echo (skipped, not validated — see servhello.go doc)
	pos += 2      // cipher_suite
	pos++         // compression_method
	if len(body) < pos+2 {
		return nil, errors.New("mirage: truncated server hello")
	}
	extsLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if len(body) < pos+extsLen {
		return nil, errors.New("mirage: truncated server hello extensions")
	}
	exts := body[pos : pos+extsLen]

	for len(exts) >= 4 {
		etype := binary.BigEndian.Uint16(exts[0:2])
		elen := int(binary.BigEndian.Uint16(exts[2:4]))
		if len(exts) < 4+elen {
			return nil, errors.New("mirage: truncated extension")
		}
		edata := exts[4 : 4+elen]
		if etype == extKeyShare && len(edata) >= 4 {
			group := binary.BigEndian.Uint16(edata[0:2])
			klen := int(binary.BigEndian.Uint16(edata[2:4]))
			if group == groupX25519 && len(edata) >= 4+klen {
				esPub = append([]byte(nil), edata[4:4+klen]...)
			}
		}
		exts = exts[4+elen:]
	}
	if len(esPub) != 32 {
		return nil, errors.New("mirage: no x25519 key_share in server hello")
	}
	return esPub, nil
}

func readContinuationRecord(r io.Reader) (tag2 []byte, err error) {
	hdr := make([]byte, 5)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 0x17 {
		return nil, errors.New("mirage: not a continuation record")
	}
	n := binary.BigEndian.Uint16(hdr[3:5])
	if n != 16 {
		return nil, errors.New("mirage: unexpected continuation record length")
	}
	tag2 = make([]byte, n)
	if _, err = io.ReadFull(r, tag2); err != nil {
		return nil, err
	}
	return tag2, nil
}

// proxyServerHello читает ServerHello от реального сайта, подменяет
// key_share на наш esPub, а random[0:16] на наш tag2.
func proxyServerHello(dest io.Reader, esPub, tag2 []byte) ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(dest, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 0x16 {
		return nil, errors.New("not a handshake record from dest")
	}
	n := binary.BigEndian.Uint16(hdr[3:5])
	body := make([]byte, n)
	if _, err := io.ReadFull(dest, body); err != nil {
		return nil, err
	}
	if body[0] != 0x02 {
		return nil, errors.New("not a ServerHello from dest")
	}

	pos := 4
	if pos+2+32 > len(body) { return nil, errors.New("truncated ServerHello") }
	pos += 2 // legacy_version

	copy(body[pos:pos+16], tag2)
	pos += 32 // random

	if pos+1 > len(body) { return nil, errors.New("truncated ServerHello") }
	sidLen := int(body[pos])
	pos += 1 + sidLen

	pos += 3 // cipher_suite + compression
	if pos+2 > len(body) { return nil, errors.New("truncated ServerHello") }
	extsLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2

	if pos+extsLen > len(body) { return nil, errors.New("truncated ServerHello") }
	exts := body[pos : pos+extsLen]

	foundKS := false
	epos := 0
	for epos+4 <= len(exts) {
		etype := binary.BigEndian.Uint16(exts[epos : epos+2])
		elen := int(binary.BigEndian.Uint16(exts[epos+2 : epos+4]))
		if epos+4+elen > len(exts) { break }
		if etype == extKeyShare {
			ksData := exts[epos+4 : epos+4+elen]
			if len(ksData) >= 4 {
				klen := int(binary.BigEndian.Uint16(ksData[2:4]))
				if klen >= 32 && len(ksData) >= 4+klen {
					copy(ksData[4:4+32], esPub)
					foundKS = true
				}
			}
		}
		epos += 4 + elen
	}
	if !foundKS {
		return nil, errors.New("no key_share (>=32 bytes) in dest ServerHello")
	}

	record := make([]byte, 5+len(body))
	copy(record, hdr)
	copy(record[5:], body)
	return record, nil
}

// parseRealityServerHello читает Reality-стиль ServerHello.
func parseRealityServerHello(r io.Reader) (esPub, tag2 []byte, err error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, nil, err
	}
	if hdr[0] != 0x16 {
		return nil, nil, errors.New("not a handshake record")
	}
	n := binary.BigEndian.Uint16(hdr[3:5])
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, nil, err
	}
	if body[0] != 0x02 {
		return nil, nil, errors.New("not a ServerHello")
	}

	pos := 6 // type(1) + len(3) + version(2)
	if pos+32 > len(body) { return nil, nil, errors.New("truncated ServerHello") }
	tag2 = make([]byte, 16)
	copy(tag2, body[pos:pos+16])
	pos += 32

	sidLen := int(body[pos])
	pos += 1 + sidLen + 3
	if pos+2 > len(body) { return nil, nil, errors.New("truncated ServerHello") }
	extsLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	exts := body[pos : pos+extsLen]

	epos := 0
	for epos+4 <= len(exts) {
		etype := binary.BigEndian.Uint16(exts[epos : epos+2])
		elen := int(binary.BigEndian.Uint16(exts[epos+2 : epos+4]))
		if epos+4+elen > len(exts) { break }
		if etype == extKeyShare {
			ksData := exts[epos+4 : epos+4+elen]
			if len(ksData) >= 4 {
				klen := int(binary.BigEndian.Uint16(ksData[2:4]))
				if klen >= 32 && len(ksData) >= 4+klen {
					esPub = make([]byte, 32)
					copy(esPub, ksData[4:4+32])
				}
			}
		}
		epos += 4 + elen
	}
	if esPub == nil {
		return nil, nil, errors.New("no key_share (>=32 bytes) found")
	}
	return esPub, tag2, nil
}
