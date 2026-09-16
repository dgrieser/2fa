// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Base32 encodings of the ASCII secrets used by the RFC 6238 test vectors:
// "12345678901234567890" repeated as needed to fill each hash's block size.
const (
	secret1   = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	secret256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA===="
	secret512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA="
)

// TestHOTP checks the test vectors from RFC 4226, Appendix D.
func TestHOTP(t *testing.T) {
	key := decode(t, secret1)
	codes := []int{755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489}
	for counter, want := range codes {
		if have := hotp(key, uint64(counter), 6, sha1.New); have != want {
			t.Errorf("hotp(counter=%d) = %06d, want %06d", counter, have, want)
		}
	}
}

// TestTOTP checks the test vectors from RFC 6238, Appendix B.
// The 20000000000 row is omitted: totp converts through UnixNano,
// which overflows past the year 2262.
func TestTOTP(t *testing.T) {
	algs := []struct {
		name   string
		secret string
		alg    func() hash.Hash
		codes  []int
	}{
		{"sha1", secret1, sha1.New, []int{94287082, 7081804, 14050471, 89005924, 69279037}},
		{"sha256", secret256, sha256.New, []int{46119246, 68084774, 67062674, 91819424, 90698825}},
		{"sha512", secret512, sha512.New, []int{90693936, 25091201, 99943326, 93441116, 38618901}},
	}
	times := []int64{59, 1111111109, 1111111111, 1234567890, 2000000000}
	for _, a := range algs {
		key := decode(t, a.secret)
		for i, sec := range times {
			want := a.codes[i]
			if have := totp(key, time.Unix(sec, 0), 8, a.alg); have != want {
				t.Errorf("totp(%s, t=%d) = %08d, want %08d", a.name, sec, have, want)
			}
		}
	}
}

func TestReadKeychain(t *testing.T) {
	data := "" +
		"old 8 " + secret1 + "\n" +
		"new 8 " + secret1 + " sha1\n" +
		"mid 8 " + secret256 + " sha256\n" +
		"big 6 " + secret512 + " sha512\n" +
		"counter 8 " + secret1 + " 00000000000000000000\n" +
		"countermid 8 " + secret256 + " sha256 00000000000000000000\n" +
		"badalg 8 " + secret1 + " sha3\n"

	file := filepath.Join(t.TempDir(), ".2fa")
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	c := readKeychain(file)

	// Every key but badalg parses, with sha1 as the default algorithm.
	tests := []struct {
		name    string
		digits  int
		code    int // code at counter 1, the RFC 6238 t=59 vector
		counter bool
	}{
		{"old", 8, 94287082, false},
		{"new", 8, 94287082, false},
		{"mid", 8, 46119246, false},
		{"big", 6, 693936, false},
		{"counter", 8, 94287082, true},
		{"countermid", 8, 46119246, true},
	}
	for _, tt := range tests {
		k, ok := c.keys[tt.name]
		if !ok {
			t.Errorf("key %q missing", tt.name)
			continue
		}
		if k.digits != tt.digits {
			t.Errorf("key %q digits = %d, want %d", tt.name, k.digits, tt.digits)
		}
		if have := hotp(k.raw, 1, k.digits, k.hash); have != tt.code {
			t.Errorf("key %q code = %0*d, want %0*d", tt.name, k.digits, have, k.digits, tt.code)
		}
		if tt.counter != (k.offset != 0) {
			t.Errorf("key %q counter = %v, want %v", tt.name, k.offset != 0, tt.counter)
		}
		if tt.counter {
			if have := string(c.data[k.offset : k.offset+counterLen]); have != "00000000000000000000" {
				t.Errorf("key %q counter at offset %d = %q", tt.name, k.offset, have)
			}
		}
	}
	if _, ok := c.keys["badalg"]; ok {
		t.Errorf("key with unknown hash was accepted")
	}
}

func decode(t *testing.T, key string) []byte {
	t.Helper()
	raw, err := decodeKey(key)
	if err != nil {
		t.Fatalf("decodeKey(%q): %v", key, err)
	}
	return raw
}

func TestRemove(t *testing.T) {
	data := "" +
		"one 6 " + secret1 + "\n" +
		"two 8 " + secret256 + " sha256\n" +
		"three 6 " + secret1 + " 00000000000000000000\n"

	file := filepath.Join(t.TempDir(), ".2fa")
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	readKeychain(file).remove("two")

	want := "" +
		"one 6 " + secret1 + "\n" +
		"three 6 " + secret1 + " 00000000000000000000\n"
	have, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(have) != want {
		t.Errorf("keychain after remove =\n%s\nwant\n%s", have, want)
	}

	// The remaining keys, including the counter offset, still parse.
	c := readKeychain(file)
	if len(c.keys) != 2 {
		t.Errorf("keychain has %d keys, want 2", len(c.keys))
	}
	if k := c.keys["three"]; string(c.data[k.offset:k.offset+counterLen]) != "00000000000000000000" {
		t.Errorf("key \"three\" counter at offset %d = %q", k.offset, c.data[k.offset:k.offset+counterLen])
	}

	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("keychain mode = %v, want -rw-------", fi.Mode().Perm())
	}
}
