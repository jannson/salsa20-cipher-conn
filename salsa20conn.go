package salsa20conn

import (
	"crypto/cipher"

	"github.com/templexxx/xor"
	"golang.org/x/crypto/salsa20"
)

type salsa20Stream struct {
	nonce []byte
	buf   []byte
	dst   []byte
	pos   int
	key   [32]byte
}

func newSalsa20Stream(key []byte, nonce []byte, iv []byte) cipher.Stream {
	s := &salsa20Stream{
		nonce: make([]byte, 8),
		//buf 记录上次 salsa20 加密之后的结果值
		buf: make([]byte, 16),
		//dst 记录上次加密之后，xor 之后的结果值
		dst: make([]byte, 16),
		//
		pos: 0,
	}
	copy(s.key[:], s.key[:32])
	copy(s.nonce, s.nonce[:8])
	copy(s.dst, iv[:16])

	salsa20.XORKeyStream(s.buf, s.dst, s.nonce, &s.key)
	//log.Println(s.buf)

	return s
}

func (s *salsa20Stream) XORKeyStream(dst, src []byte) {
	//log.Println("xor key", s.pos, len(dst), len(src))
	const blocksize = 16
	n := len(dst)
	tbl := s.buf
	if s.pos > 0 {
		left := blocksize - s.pos
		if n < left {
			//log.Println("f1", s.pos, n)
			xor.BytesSrc0(dst[0:n], src[0:n], tbl[s.pos:s.pos+n])
			copy(s.dst[s.pos:s.pos+n], dst[0:n])
			s.pos += n
			if s.pos == blocksize {
				//log.Println("f2")
				//new encrypt
				salsa20.XORKeyStream(tbl, s.dst, s.nonce, &s.key)
				s.pos = 0
			}
			return
		}

		//log.Println("f3", s.pos, left)
		xor.BytesSrc0(dst[0:left], src[0:left], tbl[s.pos:blocksize])
		copy(s.dst[s.pos:blocksize], dst[0:left])
		dst = dst[left:]
		src = src[left:]
		n -= left

		//new encrypt
		salsa20.XORKeyStream(tbl, s.dst, s.nonce, &s.key)
	}

	n = len(dst) / blocksize
	s.pos = len(dst) - n*blocksize
	base := 0
	for i := 0; i < n; i++ {
		//log.Println("f4")
		xor.BytesSrc1(dst[base:base+blocksize], src[base:base+blocksize], tbl)
		salsa20.XORKeyStream(tbl, dst[base:base+blocksize], s.nonce, &s.key)
		//log.Println(tbl)
		base += blocksize
	}
	if s.pos > 0 {
		//log.Println("f5", s.pos, base)
		xor.BytesSrc0(dst[base:], src[base:], tbl[0:s.pos])
		copy(s.dst[0:s.pos], dst[base:])
		//log.Println(s.dst)
	}
}
