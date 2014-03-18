package murmurhash3

import (
  "testing"
  "encoding/binary"
  //"crypto/rand"
)

// Makes sure that the hash produces a correct result
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

func BenchmarkMurmur128(b *testing.B) {
  const keyBytes int64 = 128
  b.SetBytes(keyBytes)
  r := make([]byte, keyBytes)
  b.ResetTimer()
  for i := 0; i < b.N; i++ {
    //binary.LittleEndian.PutUint64(r, uint64(i))
    h := New(uint64(0))
    h.Write(r)
    h.Sum(nil)
  }
}
