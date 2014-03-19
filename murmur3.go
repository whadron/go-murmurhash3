/*

TODO: After each write we need to store the 'tail'
so we can append it to the next write or run it
when the user asks for the Sum

*/



// Package murmur3 implements the murmur3 hash algorithm
package murmurhash3

import (
  "encoding/binary"
  "hash"
)

const (
  c1 uint64 = 0x87c37b91114253d5
  c2 uint64 = 0x4cf5ad432745937f
)

// 128-bit Hash interface
type Hash128 interface {
  hash.Hash
  Sum128() []byte
}

// Murmur type
type murmur128 struct {
  h1        uint64
  h2        uint64
  size      int
  blockSize int
  tlen      int
  tail      []byte
}

func New(seed int) Hash128 {
  m := new(murmur128)
  m.h1        = uint64(seed)
  m.h2        = uint64(seed)
  m.size      = 128
  m.blockSize = 64
  m.tlen      = 0
  m.tail      = nil
  return m
}


func body(h1, h2, k1, k2 uint64) (uint64, uint64) {
  k1 *= c1
  k1 = (k1 << 31) | (k1 >> 33)
  k1 *= c2
  h1 ^= k1

  h1 = (h1 << 27 | h1 >> 37)
  h1 += h2
  h1 = h1*5 + 0x52dce729

  k2 *= c2
  k2 = (k2 << 33 | k2 >> 31)
  k2 *= c1
  h2 ^= k2

  h2 = (h2 << 31 | h2 >> 33)
  h2 += h1
  h2 = h2*5 + 0x38495ab5

  return h1, h2
}

// Writes p to the hash function, returning number of bytes written
// and an error that's almost always nil
func (m *murmur128) Write(p []byte) (n int, err error) {
  h1, h2 := m.h1, m.h2
  plen := len(p)
  nblocks := plen/16

  // If we have a tail, use it as a head
  if m.tail != nil {
    // Append head to m.tail
    hlen := 16-len(m.tail)
    head := p[:hlen]
    m.tail = append(m.tail, head...)

    // Run the body one time
    k1 := binary.LittleEndian.Uint64(m.tail[:8])
    k2 := binary.LittleEndian.Uint64(m.tail[8:])
    h1, h2 = body(h1, h2, k1, k2)

    // Remove head from p
    p = p[hlen:]

    // Remove tail
    m.tail = nil
  }

  // Body
  for i := 0; i < nblocks; i++ {
    //t := (*[2]uint64)(unsafe.Pointer(&p[i*16]))
    //k1, k2 := t[0], t[1]
    k1 := binary.LittleEndian.Uint64(p[(i*16):])
    k2 := binary.LittleEndian.Uint64(p[(i*16 + 8):])
    h1, h2 = body(h1, h2, k1, k2)
  }

  // Store result
  m.h1 = h1
  m.h2 = h2

  // If we have some trailing bytes after the blocks are finished
  // we store them in m.tail for further use
  if (plen & 15) != 0 {
    m.tail = p[nblocks*16:]
  }

  // Keep track of length
  m.tlen += plen
  return plen, nil
}

func (m *murmur128) processTail() (uint64, uint64) {
  tail := m.tail
  h1, h2 := m.h1, m.h2

  var k1 uint64 = 0
  var k2 uint64 = 0

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
    k2 ^= uint64(tail[9])  << 8
    fallthrough
  case 9:
    k2 ^= uint64(tail[8])  << 0
    k2 *= c2
    k2 = (k2 << 33) | (k2 >> 31)
    k2 *= c1
    h2 ^= k2
    fallthrough
  case 8:
    k1 ^= uint64(tail[7])  << 56
    fallthrough
  case 7:
    k1 ^= uint64(tail[6])  << 48
    fallthrough
  case 6:
    k1 ^= uint64(tail[5])  << 40
    fallthrough
  case 5:
    k1 ^= uint64(tail[4])  << 32
    fallthrough
  case 4:
    k1 ^= uint64(tail[3])  << 24
    fallthrough
  case 3:
    k1 ^= uint64(tail[2])  << 16
    fallthrough
  case 2:
    k1 ^= uint64(tail[1])  << 8
    fallthrough
  case 1:
    k1 ^= uint64(tail[0])  << 0
    k1 *= c1
    k1 = (k1 << 31) | (k1 >> 33)
    k1 *= c2
    h1 ^= k1
  }

  return h1, h2
}

func finalize(h1, h2, tlen uint64) (uint64, uint64) {
  h1 ^= tlen
  h2 ^= tlen
  h1 += h2
  h2 += h1
  h1 = fmix(h1)
  h2 = fmix(h2)
  h1 += h2
  h2 += h1
  return h1, h2
}

// Returns the hash of the data input into the Hash so far
func (m *murmur128) Sum(in []byte) []byte {
  // If we have a tail, process it
  h1, h2 := m.processTail()

  // Finalize
  h1, h2 = finalize(h1, h2, uint64(m.tlen))

  return append(in,
    byte(h1>> 0), byte(h1>> 8), byte(h1>>16), byte(h1>>24),
    byte(h1>>32), byte(h1>>40), byte(h1>>48), byte(h1>>56),
    byte(h2>> 0), byte(h2>> 8), byte(h2>>16), byte(h2>>24),
    byte(h2>>32), byte(h2>>40), byte(h2>>48), byte(h2>>56),
  )
}

// Returns the 128-bit hash result
func (m *murmur128) Sum128() []byte {
  bytes := make([]byte, 16)
  return m.Sum(bytes)
}

// Resets the Hash to it's initial state
func (m *murmur128) Reset() {
  m.h1   = 0
  m.h2   = 0
  m.tlen = 0
}

// Returns the size of the Hash
func (m *murmur128) Size() int {
  return m.size
}

// Returns the blocksize of the Hash
func (m *murmur128) BlockSize() int {
  return m.blockSize
}

// Rotate left
func rotl64(x uint64, r uint8) uint64 {
  return (x << r) | (x >> (64 - r))
}

// Mix function
func fmix(k uint64) uint64 {
  k ^= k >> 33
  k *= 0xff51afd7ed558ccd
  k ^= k >> 33
  k *= 0xc4ceb9fe1a85ec53
  k ^= k >> 33
  return k
}














