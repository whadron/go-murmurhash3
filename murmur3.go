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

// 128-bit Hash interface that also implements
// hash.Hash64 for greater simplicity
type Hash128 interface {
  hash.Hash64
  Sum128() []byte
}

type murmur128 struct {
  h1        uint64
  h2        uint64
  size      int
  blockSize int
  tlength   int
}

func New(seed uint64) Hash128 {
  m := new(murmur128)
  m.h1        = seed
  m.h2        = seed
  m.size      = 128
  m.blockSize = 64
  m.tlength   = 0
  return m
}


// Writes p to the hash function, returning number of bytes written
// and an error that's almost always nil
func (m *murmur128) Write(p []byte) (n int, err error) {
  var (
    h1      uint64 = m.h1
    h2      uint64 = m.h2
    length  int    = len(p)
    nblocks int    = length / 16
  )
  const (
    c1 uint64 = 0x87c37b91114253d5
    c2 uint64 = 0x4cf5ad432745937f
  )

  // Body
  for i := 0; i < nblocks; i++ {
    var (
      k1 uint64 = binary.LittleEndian.Uint64(p[(i*2+0)*8:])
      k2 uint64 = binary.LittleEndian.Uint64(p[(i*2+1)*8:])
    )

    k1 *= c1
    k1 = rotl64(k1, 31)
    k1 *= c2
    h1 ^= k1

    h1 = rotl64(h1, 27)
    h1 += h2
    h1 = h1 * 5 + 0x52dce729

    k2 *= c2;
    k2 = rotl64(k2, 33)
    k2 *= c1
    h2 ^= k2

    h2 = rotl64(h2, 31)
    h2 += h1
    h2 = h2 * 5 + 0x38495ab5
  }

  // Tail
  // If we have some trailing bytes after the blocks (which are a fixed size)
  // are finished, this is what happens to those trailing bytes
  var (
    tail []byte = p[nblocks*16:]
    k1   uint64 = 0
    k2   uint64 = 0
  )
  switch length & 15 {
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
    k2 = rotl64(k2, 33)
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
    k1 = rotl64(k1, 31)
    k1 *= c2
    h1 ^= k1
  }
  m.h1 = h1
  m.h2 = h2
  m.tlength += length
  return length, nil
}

// Returns the hash of the data input into the Hash so far
func (m *murmur128) Sum(in []byte) []byte {
  // Finalize
  var (
    inLen int
    h1    uint64 = m.h1
    h2    uint64 = m.h2
  )

  if in != nil {
    inLen = len(in)
  } else {
    inLen = 16
  }

  h1 ^= uint64(m.tlength)
  h2 ^= uint64(m.tlength)
  h1 += h2
  h2 += h1
  h1 = fmix(h1)
  h2 = fmix(h2)
  h1 += h2
  h2 += h1

  bytes := make([]byte, inLen)
  binary.LittleEndian.PutUint64(bytes, h1)
  // Allows Hash64 interfaceability
  if inLen > 8 {
    binary.LittleEndian.PutUint64(bytes[8:], h2)
  }
  return append(in, bytes...)
}

// Returns the 128-bit hash result
func (m *murmur128) Sum128() []byte {
  bytes := make([]byte, 16)
  return m.Sum(bytes)
}

// Returns the 64-bit hash result
func (m *murmur128) Sum64() uint64 {
  bytes := make([]byte, 8)
  return binary.LittleEndian.Uint64(m.Sum(bytes))
}

// Resets the Hash to it's initial state
func (m *murmur128) Reset() {
  m.h1      = 0
  m.h2      = 0
  m.tlength = 0
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














