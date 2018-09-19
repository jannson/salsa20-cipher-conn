package salsa20conn

import (
	"crypto/cipher"

	"github.com/templexxx/xor"
	"golang.org/x/crypto/salsa20"
)

const blocksize = 16

type salsa20Stream struct {
	nonce []byte
	//当前可以用于 xor 的数据
	tbl []byte
	//salsa20 解密之后的数据
	next []byte
	pb   []byte
	pos  int
	key  [32]byte
	enc  int
}
type fSalsa20Xor func(s *salsa20Stream, dst, src []byte)

var salsa20XorFuncs [2]fSalsa20Xor

func init() {
	salsa20XorFuncs[0] = salsa20XORKeyStreamDec
	salsa20XorFuncs[1] = salsa20XORKeyStreamEnc
}

func newSalsa20Stream(key []byte, nonce []byte, iv []byte, enc bool) cipher.Stream {
	buf := make([]byte, blocksize*3)
	s := &salsa20Stream{
		nonce: make([]byte, 8),
		//tbl 记录上次 salsa20 加密之后的结果值
		tbl:  buf[0:blocksize],
		next: buf[blocksize : blocksize*2],
		//pb 记录上次加解密之后，未形成整块的值
		pb: buf[blocksize*2 : blocksize*3],
		// 记录当前的位置
		pos: 0,
	}
	copy(s.key[:], s.key[:32])
	copy(s.nonce, s.nonce[:8])

	if enc {
		s.enc = 1
	} else {
		s.enc = 0
	}

	salsa20.XORKeyStream(s.tbl, iv[:blocksize], s.nonce, &s.key)

	return s
}

func salsa20XORKeyStreamEnc(s *salsa20Stream, dst, src []byte) {
	n := len(dst)
	tbl := s.tbl
	if s.pos > 0 {
		// 表示上次加密，遗留了一下未满 16 字节的数据，需要在这里完成遗留的数据的加密
		left := blocksize - s.pos
		if n < left {
			xor.BytesSrc0(dst[0:n], src[0:n], tbl[s.pos:s.pos+n])
			copy(s.pb[s.pos:s.pos+n], dst[0:n])
			s.pos += n
			if s.pos == blocksize {
				//new encrypt
				salsa20.XORKeyStream(tbl, s.pb, s.nonce, &s.key)
				s.pos = 0
			}
			return
		}

		xor.BytesSrc0(dst[0:left], src[0:left], tbl[s.pos:blocksize])
		copy(s.pb[s.pos:blocksize], dst[0:left])
		dst = dst[left:]
		src = src[left:]

		//new encrypt
		salsa20.XORKeyStream(tbl, s.pb, s.nonce, &s.key)
	}

	n = len(dst) / blocksize
	s.pos = len(dst) - n*blocksize
	base := 0
	for i := 0; i < n; i++ {
		xor.BytesSrc1(dst[base:base+blocksize], src[base:base+blocksize], tbl)
		salsa20.XORKeyStream(tbl, dst[base:base+blocksize], s.nonce, &s.key)
		base += blocksize
	}
	if s.pos > 0 {
		// 因为要满 16 byte 再加密一次，所以未满 16 字节的，要保留到下次加密
		xor.BytesSrc0(dst[base:], src[base:], tbl[0:s.pos])
		copy(s.pb[0:s.pos], dst[base:])
	}
}

func salsa20XORKeyStreamDec(s *salsa20Stream, dst, src []byte) {
	n := len(src)
	if s.pos > 0 {
		left := blocksize - s.pos
		if n < left {
			xor.BytesSrc0(dst[0:n], src[0:n], s.tbl[s.pos:s.pos+n])
			copy(s.pb[s.pos:s.pos+n], src[0:n])
			s.pos += n
			if s.pos == blocksize {
				salsa20.XORKeyStream(s.next, s.pb, s.nonce, &s.key)
				s.tbl, s.next = s.next, s.tbl
				s.pos = 0
			}

			return
		}

		xor.BytesSrc0(dst[0:left], src[0:left], s.tbl[s.pos:blocksize])
		copy(s.pb[s.pos:blocksize], src[0:left])
		dst = dst[left:]
		src = src[left:]

		salsa20.XORKeyStream(s.next, s.pb, s.nonce, &s.key)
		s.tbl, s.next = s.next, s.tbl
	}

	tbl := s.tbl
	next := s.next
	n = len(dst) / blocksize
	s.pos = len(dst) - n*blocksize
	base := 0
	for i := 0; i < n; i++ {
		//先把密文解密
		salsa20.XORKeyStream(next, src[base:base+blocksize], s.nonce, &s.key)
		//xor 得到原始数据
		xor.BytesSrc1(dst[base:base+blocksize], src[base:base+blocksize], tbl)
		tbl, next = next, tbl
		base += blocksize
	}
	s.tbl = tbl
	s.next = next
	if s.pos > 0 {
		// 因为要满 16 byte 再加密一次，所以未满 16 字节的，要保留到下次加密
		xor.BytesSrc0(dst[base:], src[base:], tbl[0:s.pos])
		copy(s.pb[0:s.pos], src[base:])
	}
}

func (s *salsa20Stream) XORKeyStream(dst, src []byte) {
	salsa20XorFuncs[s.enc](s, dst, src)
}
