package vmess

import (
	"encoding/binary"
	"io"
)

// VMess AEAD response-header KDF labels (documented VMess AEAD scheme, as used
// by sing-vmess; sendAEADResponseHeader builds this).
const (
	labelRespLenKey = "AEAD Resp Header Len Key"
	labelRespLenIV  = "AEAD Resp Header Len IV"
	labelRespKey    = "AEAD Resp Header Key"
	labelRespIV     = "AEAD Resp Header IV"
)

// sendAEADResponseHeader writes the AEAD-encrypted response header. The response
// key/iv are SHA-256 reductions of the request body key/iv; the header itself is
// an AEAD-protected length followed by the AEAD-protected header bytes, each
// keyed by KDF(respBodyKey/IV, label).
//
// respVer must echo the request's ResponseVer byte so the client accepts it.
func sendAEADResponseHeader(w io.Writer, reqKey, reqIV [16]byte, respVer byte) error {
	respKey, respIV := responseBodyKeyIV(reqKey, reqIV)

	// header payload: responseVer, option(0), command(0), commandLen(0)
	header := []byte{respVer, 0x00, 0x00, 0x00}

	lenKey := kdf(respKey[:], labelRespLenKey)[:16]
	lenNonce := kdf(respIV[:], labelRespLenIV)[:12]
	lenAEAD, err := newDataAEAD(lenKey)
	if err != nil {
		return err
	}
	var lenPlain [2]byte
	binary.BigEndian.PutUint16(lenPlain[:], uint16(len(header)))
	encLen := lenAEAD.Seal(nil, lenNonce, lenPlain[:], nil)

	hKey := kdf(respKey[:], labelRespKey)[:16]
	hNonce := kdf(respIV[:], labelRespIV)[:12]
	hAEAD, err := newDataAEAD(hKey)
	if err != nil {
		return err
	}
	encHdr := hAEAD.Seal(nil, hNonce, header, nil)

	if _, err := w.Write(encLen); err != nil {
		return err
	}
	_, err = w.Write(encHdr)
	return err
}
