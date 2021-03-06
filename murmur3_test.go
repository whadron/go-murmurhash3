package murmurhash3

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

const (
	expected128X64 uint32 = 0x6384BA69
	expected128X86 uint32 = 0xB3ECE62A
	expected32X86  uint32 = 0xB0F57EE3
	hashbytes128   int    = 128 / 8
	hashbytes32    int    = 32 / 8
)

func TestValidityX86_32(t *testing.T) {
	key := make([]byte, 0, 256)
	hashes := make([]byte, hashbytes32*256)
	for i := 0; i < 256; i++ {
		key = append(key, byte(i))
		h := NewX86_32(256 - i)
		h.Write(key[:i])
		copy(hashes[(i*hashbytes32):], h.Sum(nil))
	}
	h := NewX86_32(0)
	h.Write(hashes)
	final := h.Sum(nil)
	verification := binary.LittleEndian.Uint32(final)
	if verification != expected32X86 {
		t.Errorf("Expected: 0x%x Verification: 0x%x",
			expected32X86, verification)
	}
}

// Makes sure that the hash produces a correct result according to the spec
func TestValidityX86_128(t *testing.T) {
	key := make([]byte, 0, 256)
	hashes := make([]byte, hashbytes128*256)
	for i := 0; i < 256; i++ {
		key = append(key, byte(i))
		h := NewX86_128(256 - i)
		h.Write(key[:i])
		copy(hashes[(i*hashbytes128):], h.Sum(nil))
	}
	h := NewX86_128(0)
	h.Write(hashes)
	final := h.Sum(nil)
	verification := binary.LittleEndian.Uint32(final)
	if verification != expected128X86 {
		t.Errorf("Expected: 0x%x Verification: 0x%x",
			expected128X86, verification)
	}
}

// Makes sure that the hash produces a correct result according to the spec
func TestValidityX64_128(t *testing.T) {
	key := make([]byte, 0, 256)
	hashes := make([]byte, hashbytes128*256)
	for i := 0; i < 256; i++ {
		key = append(key, byte(i))
		h := NewX64_128(256 - i)
		h.Write(key[:i])
		copy(hashes[(i*hashbytes128):], h.Sum(nil))
	}
	h := NewX64_128(0)
	h.Write(hashes)
	final := h.Sum(nil)
	verification := binary.LittleEndian.Uint32(final)
	if verification != expected128X64 {
		t.Errorf("Expected: 0x%x Verification: 0x%x",
			expected128X64, verification)
	}
}

// Tests if continous Writes result in the same hash as a single Write
func TestStreaming(t *testing.T) {
	r := make([]byte, 4096)
	rand.Read(r)
	h1 := NewX64_128(0)
	h1.Write(r)
	single := h1.Sum(nil)
	middle := len(r) / 2
	h2 := NewX64_128(0)
	h2.Write(r[:middle])
	h2.Write(r[middle:])
	multi := h2.Sum(nil)
	if !bytes.Equal(single, multi) {
		t.Errorf("Single: 0x%x Multi: 0x%x", single, multi)
	}
}

// Benchmarks
var benchX86_32 = NewX86_32(0)
var benchX86_128 = NewX86_128(0)
var benchX64_128 = NewX64_128(0)
var buf = make([]byte, 8192)

func benchmarkSizeX86_32(b *testing.B, size int64) {
	b.SetBytes(size)
	sum := make([]byte, benchX86_32.Size())
	for i := 0; i < b.N; i++ {
		benchX86_32.Reset()
		benchX86_32.Write(buf[:size])
		benchX86_32.Sum(sum[:0])
	}
}

func BenchmarkX86_32_16(b *testing.B) {
	benchmarkSizeX86_32(b, 16)
}
func BenchmarkX86_32_128(b *testing.B) {
	benchmarkSizeX86_32(b, 128)
}
func BenchmarkX86_32_1024(b *testing.B) {
	benchmarkSizeX86_32(b, 1024)
}
func BenchmarkX86_32_8192(b *testing.B) {
	benchmarkSizeX86_32(b, 8192)
}

func benchmarkSizeX86_128(b *testing.B, size int64) {
	b.SetBytes(size)
	sum := make([]byte, benchX86_128.Size())
	for i := 0; i < b.N; i++ {
		benchX86_128.Reset()
		benchX86_128.Write(buf[:size])
		benchX86_128.Sum(sum[:0])
	}
}

func BenchmarkX86_128_16(b *testing.B) {
	benchmarkSizeX86_128(b, 16)
}
func BenchmarkX86_128_128(b *testing.B) {
	benchmarkSizeX86_128(b, 128)
}
func BenchmarkX86_128_1024(b *testing.B) {
	benchmarkSizeX86_128(b, 1024)
}
func BenchmarkX86_128_8192(b *testing.B) {
	benchmarkSizeX86_128(b, 8192)
}

func benchmarkSizeX64_128(b *testing.B, size int64) {
	b.SetBytes(size)
	sum := make([]byte, benchX64_128.Size())
	for i := 0; i < b.N; i++ {
		benchX64_128.Reset()
		benchX64_128.Write(buf[:size])
		benchX64_128.Sum(sum[:0])
	}
}

func BenchmarkX64_128_16(b *testing.B) {
	benchmarkSizeX64_128(b, 16)
}
func BenchmarkX64_128_128(b *testing.B) {
	benchmarkSizeX64_128(b, 128)
}
func BenchmarkX64_128_1024(b *testing.B) {
	benchmarkSizeX64_128(b, 1024)
}
func BenchmarkX64_128_8192(b *testing.B) {
	benchmarkSizeX64_128(b, 8192)
}
