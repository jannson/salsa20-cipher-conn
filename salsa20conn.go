package salsa20conn

import (
	"crypto/cipher"
	"crypto/sha1"

	xor "github.com/templexxx/xorsimd"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/salsa20"
)

const blocksize = 1024
const salt = `sH3CIVoF#rWLtJo6`

type salsa20Stream struct {
	key   [32]byte
	nonce [8]byte
	//tbl 记录上次 salsa20 加密之后的结果值
	//当前可以用于 xor 的数据
	tbl []byte
	//salsa20 解密之后的数据
	next []byte
	//pb 记录上次加解密之后，未形成整块的值
	pb []byte
	// 记录当前的位置
	pos int
	enc int
}
type fSalsa20Xor func(s *salsa20Stream, dst, src []byte)

var salsa20XorFuncs [2]fSalsa20Xor

func init() {
	salsa20XorFuncs[0] = salsa20XORKeyStreamDec
	salsa20XorFuncs[1] = salsa20XORKeyStreamEnc
}

func simxor(dst, a, b []byte) {
	var src [2][]byte
	src[0] = a
	src[1] = b
	xor.Encode(dst, src[:])
}

func NewSalsa20Stream(key []byte, nonce []byte, iv []byte, enc bool) cipher.Stream {
	buf := make([]byte, blocksize*3)
	s := &salsa20Stream{
		tbl:  buf[0:blocksize],
		next: buf[blocksize : blocksize*2],
		pb:   buf[blocksize*2 : blocksize*3],
		pos:  0,
	}
	copy(s.key[:], s.key[:32])
	copy(s.nonce[:], s.nonce[:8])
	if enc {
		s.enc = 1
	} else {
		s.enc = 0
	}

	if len(iv) < blocksize {
		iv = pbkdf2.Key(iv, []byte(salt), 16, blocksize, sha1.New)
	}

	salsa20.XORKeyStream(s.tbl, iv, s.nonce[:], &s.key)

	return s
}

func salsa20XORKeyStreamEnc(s *salsa20Stream, dst, src []byte) {
	n := len(src)
	tbl := s.tbl
	if s.pos > 0 {
		// 表示上次加密，遗留了一下未满 blocksize 字节的数据，需要在这里完成遗留的数据的加密
		left := blocksize - s.pos
		if n < left {
			simxor(dst, src, tbl[s.pos:])
			copy(s.pb[s.pos:s.pos+n], dst[0:n])
			s.pos += n
			return
		}

		simxor(dst, src, s.tbl[s.pos:])
		copy(s.pb[s.pos:blocksize], dst[0:left])
		dst = dst[left:]
		src = src[left:]

		//new encrypt
		salsa20.XORKeyStream(tbl, s.pb, s.nonce[:], &s.key)
	}

	n = len(dst) / blocksize
	s.pos = len(dst) - n*blocksize
	base := 0
	for i := 0; i < n; i++ {
		simxor(dst[base:], src[base:], tbl)
		salsa20.XORKeyStream(tbl, dst[base:base+blocksize], s.nonce[:], &s.key)
		base += blocksize
	}
	if s.pos > 0 {
		simxor(dst[base:], src[base:], tbl)
		copy(s.pb[0:s.pos], dst[base:])
	}
}

func salsa20XORKeyStreamDec(s *salsa20Stream, dst, src []byte) {
	n := len(src)
	if s.pos > 0 {
		left := blocksize - s.pos
		if n < left {
			simxor(dst, src, s.tbl[s.pos:])
			copy(s.pb[s.pos:s.pos+n], src[0:n])
			s.pos += n

			return
		}

		simxor(dst, src, s.tbl[s.pos:])

		copy(s.pb[s.pos:blocksize], src[0:left])
		dst = dst[left:]
		src = src[left:]

		salsa20.XORKeyStream(s.next, s.pb, s.nonce[:], &s.key)
		s.tbl, s.next = s.next, s.tbl
	}

	tbl := s.tbl
	next := s.next
	n = len(dst) / blocksize
	s.pos = len(dst) - n*blocksize
	base := 0
	for i := 0; i < n; i++ {
		//先把密文解密
		salsa20.XORKeyStream(next, src[base:base+blocksize], s.nonce[:], &s.key)
		//xor 得到原始数据
		simxor(dst[base:], src[base:], tbl)
		tbl, next = next, tbl
		base += blocksize
	}
	s.tbl = tbl
	s.next = next
	if s.pos > 0 {
		// 因为要满 blocksize byte 再加密一次，所以未满 blocksize 字节的，要保留到下次加密
		simxor(dst[base:], src[base:], tbl)
		copy(s.pb[0:s.pos], src[base:])
	}
}

func (s *salsa20Stream) XORKeyStream(dst, src []byte) {
	salsa20XorFuncs[s.enc](s, dst, src)
}

type salsa20Block struct {
	key   [32]byte
	nonce [8]byte
}

func (s *salsa20Block) Encrypt(dst, src []byte) {
	salsa20.XORKeyStream(dst, src, s.nonce[:], &s.key)
}

func (s *salsa20Block) Decrypt(dst, src []byte) {
	salsa20.XORKeyStream(dst, src, s.nonce[:], &s.key)
}

func (s *salsa20Block) BlockSize() int {
	return blocksize
}

func NewSalsa20Block(key []byte, nonce []byte) cipher.Block {
	s := new(salsa20Block)
	copy(s.key[:], key)
	copy(s.nonce[:], nonce)
	return s
}
