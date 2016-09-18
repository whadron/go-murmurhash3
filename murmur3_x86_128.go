package murmurhash3

import (
	"encoding/binary"
)

const (
	c1X86_128        uint32 = 0x239b961b
	c2X86_128        uint32 = 0xab0e9789
	c3X86_128        uint32 = 0x38b34ae5
	c4X86_128        uint32 = 0xa1e38b93
	sizeX86_128      int    = 128
	blockSizeX86_128 int    = 16
)

type digestX86_128 struct {
	h    [4]uint32
	tlen int
	tail []byte
}

func NewX86_128(seed int) Hash128 {
	useed := uint32(seed)
	s := [4]uint32{useed, useed, useed, useed}
	return &digestX86_128{s, 0, nil}
}

func bodyX86_128(h, k [4]uint32) [4]uint32 {
	k[0] *= c1X86_128
	k[0] = (k[0] << 15) | (k[0] >> 17)
	k[0] *= c2X86_128
	h[0] ^= k[0]

	h[0] = (h[0]<<19 | h[0]>>13)
	h[0] += h[1]
	h[0] = h[0]*5 + 0x561ccd1b

	k[1] *= c2X86_128
	k[1] = (k[1] << 16) | (k[1] >> 16)
	k[1] *= c3X86_128
	h[1] ^= k[1]

	h[1] = (h[1]<<17 | h[1]>>15)
	h[1] += h[2]
	h[1] = h[1]*5 + 0x0bcaa747

	k[2] *= c3X86_128
	k[2] = (k[2] << 17) | (k[2] >> 15)
	k[2] *= c4X86_128
	h[2] ^= k[2]

	h[2] = (h[2]<<15 | h[2]>>17)
	h[2] += h[3]
	h[2] = h[2]*5 + 0x96cd1c35

	k[3] *= c4X86_128
	k[3] = (k[3] << 18) | (k[3] >> 14)
	k[3] *= c1X86_128
	h[3] ^= k[3]

	h[3] = (h[3]<<13 | h[3]>>19)
	h[3] += h[0]
	h[3] = h[3]*5 + 0x32ac3b17

	return h
}

func (m *digestX86_128) Write(p []byte) (int, error) {
	h := m.h
	plen := len(p)
	nblocks := plen / 16
	if m.tail != nil {
		hlen := 16 - len(m.tail)
		head := p[:hlen]
		m.tail = append(m.tail, head...)
		k := [4]uint32{
			binary.LittleEndian.Uint32(m.tail[:4]),
			binary.LittleEndian.Uint32(m.tail[4:8]),
			binary.LittleEndian.Uint32(m.tail[8:12]),
			binary.LittleEndian.Uint32(m.tail[12:]),
		}
		h = bodyX86_128(h, k)
		p = p[hlen:]
		m.tail = nil
	}
	for i := 0; i < nblocks; i++ {
		k := [4]uint32{
			binary.LittleEndian.Uint32(p[(i * 16):]),
			binary.LittleEndian.Uint32(p[(i*16 + 4):]),
			binary.LittleEndian.Uint32(p[(i*16 + 8):]),
			binary.LittleEndian.Uint32(p[(i*16 + 12):]),
		}
		h = bodyX86_128(h, k)
	}
	m.h[0] = h[0]
	m.h[1] = h[1]
	m.h[2] = h[2]
	m.h[3] = h[3]
	m.tlen += plen
	if (plen & 15) != 0 {
		m.tail = p[nblocks*16:]
	}
	return plen, nil
}

func (m *digestX86_128) processTail() [4]uint32 {
	tail := m.tail
	h := m.h
	k1 := uint32(0)
	k2 := uint32(0)
	k3 := uint32(0)
	k4 := uint32(0)
	switch m.tlen & 15 {
	case 15:
		k4 ^= uint32(tail[14]) << 16
		fallthrough
	case 14:
		k4 ^= uint32(tail[13]) << 8
		fallthrough
	case 13:
		k4 ^= uint32(tail[12]) << 0
		k4 *= c4X86_128
		k4 = (k4 << 18) | (k4 >> 14)
		k4 *= c1X86_128
		h[3] ^= k4
		fallthrough
	case 12:
		k3 ^= uint32(tail[11]) << 24
		fallthrough
	case 11:
		k3 ^= uint32(tail[10]) << 16
		fallthrough
	case 10:
		k3 ^= uint32(tail[9]) << 8
		fallthrough
	case 9:
		k3 ^= uint32(tail[8]) << 0
		k3 *= c3X86_128
		k3 = (k3 << 17) | (k3 >> 15)
		k3 *= c4X86_128
		h[2] ^= k3
		fallthrough
	case 8:
		k2 ^= uint32(tail[7]) << 24
		fallthrough
	case 7:
		k2 ^= uint32(tail[6]) << 16
		fallthrough
	case 6:
		k2 ^= uint32(tail[5]) << 8
		fallthrough
	case 5:
		k2 ^= uint32(tail[4]) << 0
		k2 *= c2X86_128
		k2 = (k2 << 16) | (k2 >> 16)
		k2 *= c3X86_128
		h[1] ^= k2
		fallthrough
	case 4:
		k1 ^= uint32(tail[3]) << 24
		fallthrough
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0]) << 0
		k1 *= c1X86_128
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2X86_128
		h[0] ^= k1
	}
	return h
}

func finalX86_128(h [4]uint32, tlen uint32) [4]uint32 {
	h[0] ^= tlen
	h[1] ^= tlen
	h[2] ^= tlen
	h[3] ^= tlen

	h[0] += h[1]
	h[0] += h[2]
	h[0] += h[3]
	h[1] += h[0]
	h[2] += h[0]
	h[3] += h[0]

	h[0] = fmix32(h[0])
	h[1] = fmix32(h[1])
	h[2] = fmix32(h[2])
	h[3] = fmix32(h[3])

	h[0] += h[1]
	h[0] += h[2]
	h[0] += h[3]
	h[1] += h[0]
	h[2] += h[0]
	h[3] += h[0]
	return h
}

// Returns the hash of the data input into the Hash so far
func (m *digestX86_128) Sum(in []byte) []byte {
	h := m.processTail()
	h = finalX86_128(h, uint32(m.tlen))
	return append(in,
		byte(h[0]>>0), byte(h[0]>>8), byte(h[0]>>16), byte(h[0]>>24),
		byte(h[1]>>0), byte(h[1]>>8), byte(h[1]>>16), byte(h[1]>>24),
		byte(h[2]>>0), byte(h[2]>>8), byte(h[2]>>16), byte(h[2]>>24),
		byte(h[3]>>0), byte(h[3]>>8), byte(h[3]>>16), byte(h[3]>>24),
	)
}

func (m *digestX86_128) Sum128() []byte {
	bytes := make([]byte, 16)
	return m.Sum(bytes)
}

func (m *digestX86_128) Reset() {
	m.h[0] = 0
	m.h[1] = 0
	m.h[2] = 0
	m.h[3] = 0
	m.tlen = 0
	m.tail = nil
}

func (m *digestX86_128) Size() int { return sizeX86_128 }

func (m *digestX86_128) BlockSize() int { return blockSizeX86_128 }
