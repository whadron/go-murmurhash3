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
    h := New(uint64(256-i))
    h.Write(key[:i])
    copy(hashes[(i*hashbytes):], h.Sum(nil))
  }

  h := New(uint64(0))
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

  // Add random bytes to r
  _, err := rand.Read(r)
  if err != nil {
    t.Error("rand failed.....")
    return
  }

  // Do a single-Write hash
  h1 := New(uint64(0))
  h1.Write(r)
  single := h1.Sum(nil)

  // Do a multi-Write hash
  middle := len(r) / 2
  h2 := New(uint64(0))
  h2.Write(r[:middle])
  h2.Write(r[middle:])
  multi := h2.Sum(nil)

  // The hashes from both operations should be the same
  if !bytes.Equal(single, multi) {
    t.Errorf("single: 0x%x multi: 0x%x", single, multi)
  }
}

func BenchmarkMurmur128(b *testing.B) {
  const keyBytes int64 = 128
  b.SetBytes(keyBytes)
  r := make([]byte, keyBytes)
  b.ResetTimer()
  for i := 0; i < b.N; i++ {
    h := New(uint64(0))
    h.Write(r)
    h.Sum(nil)
  }
}
