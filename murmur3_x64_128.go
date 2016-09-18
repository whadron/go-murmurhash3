package murmurhash3

import (
	"encoding/binary"
)

const (
	c1X64_128        uint64 = 0x87c37b91114253d5
	c2X64_128        uint64 = 0x4cf5ad432745937f
	sizeX64_128      int    = 128
	blockSizeX64_128 int    = 16
)

type digestX64_128 struct {
	h1   uint64
	h2   uint64
	tlen int
	tail []byte
}

func NewX64_128(seed int) Hash128 {
	return &digestX64_128{uint64(seed), uint64(seed), 0, nil}
}

func bodyX64_128(h1, h2, k1, k2 uint64) (uint64, uint64) {
	k1 *= c1X64_128
	k1 = (k1 << 31) | (k1 >> 33)
	k1 *= c2X64_128
	h1 ^= k1

	h1 = (h1<<27 | h1>>37)
	h1 += h2
	h1 = h1*5 + 0x52dce729

	k2 *= c2X64_128
	k2 = (k2<<33 | k2>>31)
	k2 *= c1X64_128
	h2 ^= k2

	h2 = (h2<<31 | h2>>33)
	h2 += h1
	h2 = h2*5 + 0x38495ab5

	return h1, h2
}

func (m *digestX64_128) Write(p []byte) (n int, err error) {
	h1, h2 := m.h1, m.h2
	plen := len(p)
	nblocks := plen / 16
	if m.tail != nil {
		hlen := 16 - len(m.tail)
		head := p[:hlen]
		m.tail = append(m.tail, head...)
		k1 := binary.LittleEndian.Uint64(m.tail[:8])
		k2 := binary.LittleEndian.Uint64(m.tail[8:])
		h1, h2 = bodyX64_128(h1, h2, k1, k2)
		p = p[hlen:]
		m.tail = nil
	}
	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint64(p[(i * 16):])
		k2 := binary.LittleEndian.Uint64(p[(i*16 + 8):])
		h1, h2 = bodyX64_128(h1, h2, k1, k2)
	}
	m.h1 = h1
	m.h2 = h2
	m.tlen += plen
	if (plen & 15) != 0 {
		m.tail = p[nblocks*16:]
	}
	return plen, nil
}

func (m *digestX64_128) processTail() (uint64, uint64) {
	tail := m.tail
	h1, h2 := m.h1, m.h2
	k1 := uint64(0)
	k2 := uint64(0)
	switch m.tlen & 15 {
	case 15:
		k2 ^= uint64(tail[14]) << 48
		fallthrough
	case 14:
		k2 ^= uint64(tail[13]) << 40
		fallthrough
	case 13:
		k2 ^= uint64(tail[12]) << 32
		fallthrough
	case 12:
		k2 ^= uint64(tail[11]) << 24
		fallthrough
	case 11:
		k2 ^= uint64(tail[10]) << 16
		fallthrough
	case 10:
		k2 ^= uint64(tail[9]) << 8
		fallthrough
	case 9:
		k2 ^= uint64(tail[8]) << 0
		k2 *= c2X64_128
		k2 = (k2 << 33) | (k2 >> 31)
		k2 *= c1X64_128
		h2 ^= k2
		fallthrough
	case 8:
		k1 ^= uint64(tail[7]) << 56
		fallthrough
	case 7:
		k1 ^= uint64(tail[6]) << 48
		fallthrough
	case 6:
		k1 ^= uint64(tail[5]) << 40
		fallthrough
	case 5:
		k1 ^= uint64(tail[4]) << 32
		fallthrough
	case 4:
		k1 ^= uint64(tail[3]) << 24
		fallthrough
	case 3:
		k1 ^= uint64(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint64(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint64(tail[0]) << 0
		k1 *= c1X64_128
		k1 = (k1 << 31) | (k1 >> 33)
		k1 *= c2X64_128
		h1 ^= k1
	}
	return h1, h2
}

func final(h1, h2, tlen uint64) (uint64, uint64) {
	h1 ^= tlen
	h2 ^= tlen
	h1 += h2
	h2 += h1
	h1 = fmix64(h1)
	h2 = fmix64(h2)
	h1 += h2
	h2 += h1
	return h1, h2
}

// Returns the hash of the data input into the Hash so far
func (m *digestX64_128) Sum(in []byte) []byte {
	h1, h2 := m.processTail()
	h1, h2 = final(h1, h2, uint64(m.tlen))
	return append(in,
		byte(h1>>0), byte(h1>>8), byte(h1>>16), byte(h1>>24),
		byte(h1>>32), byte(h1>>40), byte(h1>>48), byte(h1>>56),
		byte(h2>>0), byte(h2>>8), byte(h2>>16), byte(h2>>24),
		byte(h2>>32), byte(h2>>40), byte(h2>>48), byte(h2>>56),
	)
}

func (m *digestX64_128) Sum128() []byte {
	bytes := make([]byte, 16)
	return m.Sum(bytes)
}

func (m *digestX64_128) Reset() {
	m.h1 = 0
	m.h2 = 0
	m.tlen = 0
	m.tail = nil
}

func (m *digestX64_128) Size() int { return sizeX64_128 }

func (m *digestX64_128) BlockSize() int { return blockSizeX64_128 }
