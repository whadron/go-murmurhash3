package murmurhash3

import (
  "testing"
  "encoding/binary"
  "crypto/rand"
  "bytes"
)

// Makes sure that the hash produces a correct result according to the spec
func TestValidity(t *testing.T) {
  const (
    expected  uint32 = 0x6384BA69
    hashbytes int    = 128 / 8
  )
  var (
    key       []byte = make([]byte, 0, 256)
    hashes    []byte = make([]byte, hashbytes*256)
  )

  for i := 0; i < 256; i++ {
    key = append(key, byte(i))
    h := New(256-i)
    h.Write(key[:i])
    copy(hashes[(i*hashbytes):], h.Sum(nil))
  }

  h := New(0)
  h.Write(hashes)
  final := h.Sum(nil)
  verification := binary.LittleEndian.Uint32(final)
  if verification != expected {
    t.Errorf("Expected: 0x%x Verification: 0x%x",
      expected, verification)
  }
}

// Tests if continous Writes result in the same hash as a single Write
func TestStreaming(t *testing.T) {
  r := make([]byte, 4096)
  rand.Read(r)

  h1 := New(0)
  h1.Write(r)
  single := h1.Sum(nil)

  middle := len(r) / 2
  h2 := New(0)
  h2.Write(r[:middle])
  h2.Write(r[middle:])
  multi := h2.Sum(nil)

  if !bytes.Equal(single, multi) {
    t.Errorf("Single: 0x%x Multi: 0x%x", single, multi)
  }
}


// Benchmarks
var bench = New(0)
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
