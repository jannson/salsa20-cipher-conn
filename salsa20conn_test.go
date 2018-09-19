package salsa20conn

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
	"testing"
)

func newSalsa20CipherPair() (cipher.Stream, cipher.Stream) {
	key := make([]byte, 32)
	nonce := make([]byte, 8)
	iv := make([]byte, 16)

	io.ReadFull(rand.Reader, key)
	io.ReadFull(rand.Reader, nonce)
	io.ReadFull(rand.Reader, iv)

	enc := newSalsa20Stream(key, nonce, iv)
	dec := newSalsa20Stream(key, nonce, iv)
	return enc, dec
}

func TestSalsa20Stream(t *testing.T) {
	enc, dec := newSalsa20CipherPair()

	s := "12345string54321string"
	b0 := []byte(s)
	log.Println("b0", b0)
	b1 := make([]byte, len(b0))
	b2 := make([]byte, len(b0))

	enc.XORKeyStream(b1, b0)
	log.Println("b1", b1)
	dec.XORKeyStream(b2, b1)
	log.Println("b2", b2)

	if !bytes.Equal(b2, b0) {
		t.Fail()
	}
}
