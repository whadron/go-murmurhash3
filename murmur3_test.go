package murmur3

import (
  "testing"
  "encoding/binary"
  "crypto/rand"
  "bytes"
)

const (
  expected128  uint32 = 0x6384BA69
  expected32   uint32 = 0xB0F57EE3
  hashbytes128 int    = 128 / 8
  hashbytes32  int    = 32 / 8
)

// Makes sure that the hash produces a correct result according to the spec
func TestValidity(t *testing.T) {
  key := make([]byte, 0, 256)
  hashes := make([]byte, hashbytes128*256)
  for i := 0; i < 256; i++ {
    key = append(key, byte(i))
    h := New128(256-i)
    h.Write(key[:i])
    copy(hashes[(i*hashbytes128):], h.Sum(nil))
  }
  h := New128(0)
  h.Write(hashes)
  final := h.Sum(nil)
  verification := binary.LittleEndian.Uint32(final)
  if verification != expected128 {
    t.Errorf("Expected: 0x%x Verification: 0x%x",
      expected128, verification)
  }
}

func TestValidity32(t *testing.T) {
  key := make([]byte, 0, 256)
  hashes := make([]byte, hashbytes32*256)
  for i := 0; i < 256; i++ {
    key = append(key, byte(i))
    h := New32(256-i)
    h.Write(key[:i])
    copy(hashes[(i*hashbytes32):], h.Sum(nil))
  }
  h := New32(0)
  h.Write(hashes)
  final := h.Sum(nil)
  verification := binary.LittleEndian.Uint32(final)
  if verification != expected32 {
    t.Errorf("Expected: 0x%x Verification: 0x%x",
      expected32, verification)
  }
}

// Tests if continous Writes result in the same hash as a single Write
func TestStreaming(t *testing.T) {
  r := make([]byte, 4096)
  rand.Read(r)
  h1 := New128(0)
  h1.Write(r)
  single := h1.Sum(nil)
  middle := len(r) / 2
  h2 := New128(0)
  h2.Write(r[:middle])
  h2.Write(r[middle:])
  multi := h2.Sum(nil)
  if !bytes.Equal(single, multi) {
    t.Errorf("Single: 0x%x Multi: 0x%x", single, multi)
  }
}

// Benchmarks
var bench = New128(0)
var buf = make([]byte, 8192)

func benchmarkSize(b *testing.B, size int64) {
  b.SetBytes(size)
  sum := make([]byte, bench.Size())
  for i := 0; i < b.N; i++ {
    bench.Reset()
    bench.Write(buf[:size])
    bench.Sum(sum[:0])
  }
}

func Benchmark16(b *testing.B)  {
  benchmarkSize(b, 16)
}
func Benchmark128(b *testing.B) {
  benchmarkSize(b, 128)
}
func Benchmark1024(b *testing.B) {
  benchmarkSize(b, 1024)
}
func Benchmark8192(b *testing.B) {
  benchmarkSize(b, 8192)
}
