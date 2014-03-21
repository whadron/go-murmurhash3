// Package murmur3 implements the murmur3 hash algorithm
package murmur3

import (
  "encoding/binary"
  "hash"
)

const (
  c1_32        uint32 = 0xcc9e2d51
  c2_32        uint32 = 0x1b873593
  size32       int    = 32
  blockSize32  int    = 4
)

type digest32 struct {
  h1        uint32
  tlen      int
  tail      []byte
}

func New32(seed int) hash.Hash32 {
  return &digest32{uint32(seed), 0, nil}
}

// (x << r) | (x >> (32 - r))
func body32(h1, k1 uint32) uint32 {
  k1 *= c1_32
  k1 = (k1 << 15) | (k1 >> 17)
  k1 *= c2_32
  h1 ^= k1
  h1 = (h1 << 13) | (h1 >> 19)
  h1 = h1*5 + 0xe6546b64
  return h1
}

// TODO: Should return err sometimes
func (m *digest32) Write(p []byte) (n int, err error) {
  h1 := m.h1
  plen := len(p)
  nblocks := plen/4
  if m.tail != nil {
    hlen := blockSize32-len(m.tail)
    head := p[:hlen]
    m.tail = append(m.tail, head...)
    k1 := binary.LittleEndian.Uint32(m.tail)
    h1 = body32(h1, k1)
    p = p[hlen:]
    m.tail = nil
  }
  for i := 0; i < nblocks; i++ {
    k1 := binary.LittleEndian.Uint32(p[(i*blockSize32):])
    h1 = body32(h1, k1)
  }
  m.h1 = h1
  m.tlen += plen
  if (plen & 3) != 0 {
    m.tail = p[nblocks*blockSize32:]
  }
  return plen, nil
}

func (m *digest32) processTail() uint32 {
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
    k1 *= c1_32
    k1 = (k1 << 15) | (k1 >> 17)
    k1 *= c2_32
    h1 ^= k1
  }
  return h1
}


// Returns the hash of the data input into the Hash so far
func (m *digest32) Sum(in []byte) []byte {
  h1 := m.processTail()
  h1 ^= uint32(m.tlen)
  h1 = fmix32(h1)
  return append(in,
    byte(h1>> 0), byte(h1>> 8), byte(h1>>16), byte(h1>>24),
  )
}

func (m *digest32) Sum32() uint32 {
  bytes := make([]byte, 4)
  bytes = m.Sum(bytes)
  return binary.LittleEndian.Uint32(bytes)
}

func (m *digest32) Reset() {
  m.h1   = 0
  m.tlen = 0
  m.tail = nil
}

func (m *digest32) Size() int { return size32 }

func (m *digest32) BlockSize() int { return blockSize32 }

func fmix32(h uint32) uint32 {
  h ^= h >> 16
  h *= 0x85ebca6b
  h ^= h >> 13
  h *= 0xc2b2ae35
  h ^= h >> 16
  return h
}















