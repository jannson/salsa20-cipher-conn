package salsa20conn

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"testing"

	"github.com/templexxx/xor"
)

func newSalsa20CipherPair() (cipher.Stream, cipher.Stream) {
	key := make([]byte, 32)
	nonce := make([]byte, 8)
	iv := make([]byte, blocksize)

	io.ReadFull(rand.Reader, key)
	io.ReadFull(rand.Reader, nonce)
	io.ReadFull(rand.Reader, iv)

	enc := NewSalsa20Stream(key, nonce, iv, true)
	dec := NewSalsa20Stream(key, nonce, iv, false)
	return enc, dec
}

func testSizeCounter(size int, cs1 []int, cs2 []int, t *testing.T) {
	enc, dec := newSalsa20CipherPair()

	b0 := make([]byte, size)
	io.ReadFull(rand.Reader, b0)

	b1 := make([]byte, len(b0))
	b2 := make([]byte, len(b0))

	for i := 1; i < len(cs1); i++ {
		enc.XORKeyStream(b1[cs1[i-1]:cs1[i]], b0[cs1[i-1]:cs1[i]])
	}

	for i := 1; i < len(cs2); i++ {
		dec.XORKeyStream(b2[cs2[i-1]:cs2[i]], b1[cs2[i-1]:cs2[i]])
	}

	if !bytes.Equal(b2, b0) {
		t.Fail()
	}
}

func TestSalsa20Bytes10(t *testing.T) {
	size := 10
	cs1 := []int{0, size}
	cs2 := []int{0, size}

	testSizeCounter(size, cs1, cs2, t)
}

func TestSalsa20Bytes16(t *testing.T) {
	size := 16
	cs1 := []int{0, size}
	cs2 := []int{0, size}

	testSizeCounter(size, cs1, cs2, t)
}

func TestSalsa20Bytes22(t *testing.T) {
	size := 22
	cs1 := []int{0, size}
	cs2 := []int{0, size}

	testSizeCounter(size, cs1, cs2, t)
}

func TestSalsa20Bytes92(t *testing.T) {
	size := 92
	cs1 := []int{0, size}
	cs2 := []int{0, size}

	testSizeCounter(size, cs1, cs2, t)
}

func TestSalsa20Count18(t *testing.T) {
	size := 18
	cs1 := []int{0, 5, size}

	testSizeCounter(size, cs1, cs1, t)

}

func TestSalsa20Count92(t *testing.T) {
	size := 92
	cs1 := []int{0, 2, 3, 11, 12, 30, 80, size}
	cs2 := []int{0, 30, 36, 56, 60, size}

	testSizeCounter(size, cs1, cs2, t)

}

func TestXor(t *testing.T) {
	size := 92
	b0 := make([]byte, size)
	b1 := make([]byte, size)
	b2 := make([]byte, size)

	io.ReadFull(rand.Reader, b0)
	io.ReadFull(rand.Reader, b1)
	io.ReadFull(rand.Reader, b2)

	xor.BytesSrc0(b0[30:], b1[31:], b2[:29])
}
