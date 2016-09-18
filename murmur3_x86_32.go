package murmurhash3

import (
	"encoding/binary"
	"hash"
)

const (
	c1X86_32        uint32 = 0xcc9e2d51
	c2X86_32        uint32 = 0x1b873593
	sizeX86_32      int    = 32
	blockSizeX86_32 int    = 4
)

type digestX86_32 struct {
	h1   uint32
	tlen int
	tail []byte
}

func NewX86_32(seed int) hash.Hash32 {
	return &digestX86_32{uint32(seed), 0, nil}
}

// (x << r) | (x >> (32 - r))
func bodyX86_32(h1, k1 uint32) uint32 {
	k1 *= c1X86_32
	k1 = (k1 << 15) | (k1 >> 17)
	k1 *= c2X86_32
	h1 ^= k1
	h1 = (h1 << 13) | (h1 >> 19)
	h1 = h1*5 + 0xe6546b64
	return h1
}

// TODO: Should return err sometimes
func (m *digestX86_32) Write(p []byte) (n int, err error) {
	h1 := m.h1
	plen := len(p)
	nblocks := plen / 4
	if m.tail != nil {
		hlen := blockSizeX86_32 - len(m.tail)
		head := p[:hlen]
		m.tail = append(m.tail, head...)
		k1 := binary.LittleEndian.Uint32(m.tail)
		h1 = bodyX86_32(h1, k1)
		p = p[hlen:]
		m.tail = nil
	}
	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint32(p[(i * blockSizeX86_32):])
		h1 = bodyX86_32(h1, k1)
	}
	m.h1 = h1
	m.tlen += plen
	if (plen & 3) != 0 {
		m.tail = p[nblocks*blockSizeX86_32:]
	}
	return plen, nil
}

func (m *digestX86_32) processTail() uint32 {
	tail := m.tail
	h1 := m.h1
	k1 := uint32(0)
	switch m.tlen & 3 {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1X86_32
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2X86_32
		h1 ^= k1
	}
	return h1
}

// Returns the hash of the data input into the Hash so far
func (m *digestX86_32) Sum(in []byte) []byte {
	h1 := m.processTail()
	h1 ^= uint32(m.tlen)
	h1 = fmix32(h1)
	return append(in,
		byte(h1>>0), byte(h1>>8), byte(h1>>16), byte(h1>>24),
	)
}

func (m *digestX86_32) Sum32() uint32 {
	bytes := make([]byte, 4)
	bytes = m.Sum(bytes)
	return binary.LittleEndian.Uint32(bytes)
}

func (m *digestX86_32) Reset() {
	m.h1 = 0
	m.tlen = 0
	m.tail = nil
}

func (m *digestX86_32) Size() int { return sizeX86_32 }

func (m *digestX86_32) BlockSize() int { return blockSizeX86_32 }
