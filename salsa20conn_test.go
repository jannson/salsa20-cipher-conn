package salsa20conn

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	mrand "math/rand"
	"testing"

	"github.com/templexxx/xor"
)

const mtuLimit = 4 * 1024 * 1024

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

func newSalsa20Iv16CipherPair() (cipher.Stream, cipher.Stream) {
	key := make([]byte, 32)
	nonce := make([]byte, 8)
	iv := make([]byte, 16)

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

func testSizeIv16Counter(size int, cs1 []int, cs2 []int, t *testing.T) {
	enc, dec := newSalsa20Iv16CipherPair()

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
	//加密的顺序与解密的顺序完全不一样的测试
	cs1 := []int{0, 2, 3, 11, 12, 30, 80, size}
	cs2 := []int{0, 30, 36, 56, 60, size}

	testSizeCounter(size, cs1, cs2, t)

}

//生成有序的 n 个不重复的序列
func genRandomSlice(size, n int) []int {
	a := make([]int, n)
	last := 1
	for i := 1; i < n-1; i++ {
		a[i] = (last + mrand.Intn(size-last-1))
		last = a[i]
	}
	a[0] = 0
	a[n-1] = size
	return a
}

func TestSalsa20CountRandom(t *testing.T) {
	size := 1024 * 1024
	n1 := 10 + (mrand.Intn(10))
	n2 := 9 + (mrand.Intn(20))

	//加密的顺序与解密的顺序完全不一样的测试
	cs1 := genRandomSlice(size, n1)
	cs2 := genRandomSlice(size, n2)

	testSizeCounter(size, cs1, cs2, t)

}

func TestSalsa20CountRandomIv16(t *testing.T) {
	size := 1024 * 1024
	n1 := 10 + (mrand.Intn(10))
	n2 := 9 + (mrand.Intn(20))

	//加密的顺序与解密的顺序完全不一样的测试
	cs1 := genRandomSlice(size, n1)
	cs2 := genRandomSlice(size, n2)

	testSizeIv16Counter(size, cs1, cs2, t)
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

func benchCrypt(b *testing.B, sEnc, sDec cipher.Stream) {
	b.ReportAllocs()
	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)

	for i := 0; i < b.N; i++ {
		sEnc.XORKeyStream(enc, data)
		sDec.XORKeyStream(dec, enc)
	}
	b.SetBytes(int64(len(enc) * 2))
}

func BenchmarkAES(b *testing.B) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	io.ReadFull(rand.Reader, key)
	io.ReadFull(rand.Reader, iv)
	b1, _ := aes.NewCipher(key)
	b2, _ := aes.NewCipher(key)
	enc := cipher.NewCFBEncrypter(b1, iv)
	dec := cipher.NewCFBDecrypter(b2, iv)

	benchCrypt(b, enc, dec)
}

func BenchmarkSalsa20(b *testing.B) {
	enc, dec := newSalsa20CipherPair()
	benchCrypt(b, enc, dec)
}
