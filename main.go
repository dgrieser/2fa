// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// 2fa is a two-factor authentication agent.
//
// Usage:
//
//	2fa -add [-7] [-8] [-hotp] [-hash alg] name
//	2fa -remove name
//	2fa -list
//	2fa [-clip] name
//
// “2fa -add name” adds a new key to the 2fa keychain with the given name.
// It prints a prompt to standard error and reads a two-factor key from standard input.
// Two-factor keys are short case-insensitive strings of letters A-Z and digits 2-7.
//
// By default the new key generates time-based (TOTP) authentication codes;
// the -hotp flag makes the new key generate counter-based (HOTP) codes instead.
//
// By default the new key generates 6-digit codes; the -7 and -8 flags select
// 7- and 8-digit codes instead.
//
// By default the new key derives codes using HMAC-SHA1, as nearly all
// two-factor providers do; the -hash flag selects sha256 or sha512 instead.
// Setting -hash to a non-default algorithm records the choice in the keychain
// alongside the key, so the algorithm only needs to be named when adding.
//
// “2fa -remove name” deletes the key with the given name from the keychain.
//
// “2fa -list” lists the names of all the keys in the keychain.
//
// “2fa name” prints a two-factor authentication code from the key with the
// given name. If “-clip” is specified, 2fa also copies the code to the system
// clipboard.
//
// With no arguments, 2fa prints two-factor authentication codes from all
// known time-based keys.
//
// The default time-based authentication codes are derived from a hash of
// the key and the current time, so it is important that the system clock have
// at least one-minute accuracy.
//
// The keychain is stored unencrypted in the text file $HOME/.2fa.
//
// # Example
//
// During GitHub 2FA setup, at the “Scan this barcode with your app” step,
// click the “enter this text code instead” link. A window pops up showing
// “your two-factor secret,” a short string of letters and digits.
//
// Add it to 2fa under the name github, typing the secret at the prompt:
//
//	$ 2fa -add github
//	2fa key for github: nzxxiidbebvwk6jb
//	$
//
// Then whenever GitHub prompts for a 2FA code, run 2fa to obtain one:
//
//	$ 2fa github
//	268346
//	$
//
// Or to type less:
//
//	$ 2fa
//	268346	github
//	$
package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"hash"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/atotto/clipboard"
)

var (
	flagAdd    = flag.Bool("add", false, "add a key")
	flagList   = flag.Bool("list", false, "list keys")
	flagRemove = flag.Bool("remove", false, "remove a key")
	flagHotp   = flag.Bool("hotp", false, "add key as HOTP (counter-based) key")
	flag7      = flag.Bool("7", false, "generate 7-digit code")
	flag8      = flag.Bool("8", false, "generate 8-digit code")
	flagClip   = flag.Bool("clip", false, "copy code to the clipboard")
	flagHash   = flag.String("hash", "sha1", "hash algorithm for new key: sha1, sha256, or sha512")
)

// hashes are the hash algorithms a key may use, keyed by the name
// recorded in the keychain.
var hashes = map[string]func() hash.Hash{
	"sha1":   sha1.New,
	"sha256": sha256.New,
	"sha512": sha512.New,
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "\t2fa -add [-7] [-8] [-hotp] [-hash alg] keyname\n")
	fmt.Fprintf(os.Stderr, "\t2fa -remove keyname\n")
	fmt.Fprintf(os.Stderr, "\t2fa -list\n")
	fmt.Fprintf(os.Stderr, "\t2fa [-clip] keyname\n")
	os.Exit(2)
}

func main() {
	log.SetPrefix("2fa: ")
	log.SetFlags(0)
	flag.Usage = usage
	flag.Parse()

	k := readKeychain(filepath.Join(os.Getenv("HOME"), ".2fa"))

	if *flagList {
		if flag.NArg() != 0 {
			usage()
		}
		k.list()
		return
	}
	if *flagAdd && *flagRemove {
		usage()
	}
	if flag.NArg() == 0 && !*flagAdd && !*flagRemove {
		if *flagClip {
			usage()
		}
		k.showAll()
		return
	}
	if flag.NArg() != 1 {
		usage()
	}
	name := flag.Arg(0)
	if strings.IndexFunc(name, unicode.IsSpace) >= 0 {
		log.Fatal("name must not contain spaces")
	}
	if *flagAdd {
		if *flagClip {
			usage()
		}
		k.add(name)
		return
	}
	if *flagRemove {
		if *flagClip {
			usage()
		}
		k.remove(name)
		return
	}
	k.show(name)
}

type Keychain struct {
	file string
	data []byte
	keys map[string]Key
}

type Key struct {
	raw    []byte
	digits int
	hash   func() hash.Hash
	offset int // offset of counter
}

const counterLen = 20

func readKeychain(file string) *Keychain {
	c := &Keychain{
		file: file,
		keys: make(map[string]Key),
	}
	data, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return c
		}
		log.Fatal(err)
	}
	c.data = data

	lines := bytes.SplitAfter(data, []byte("\n"))
	offset := 0
	for i, line := range lines {
		lineno := i + 1
		offset += len(line)
		f := bytes.Split(bytes.TrimSuffix(line, []byte("\n")), []byte(" "))
		if len(f) == 1 && len(f[0]) == 0 {
			continue
		}
		if len(f) >= 3 && len(f[1]) == 1 && '6' <= f[1][0] && f[1][0] <= '8' {
			var k Key
			name := string(f[0])
			k.digits = int(f[1][0] - '0')
			k.hash = sha1.New
			raw, err := decodeKey(string(f[2]))
			if err == nil {
				k.raw = raw
				rest := f[3:]
				// Optional hash algorithm name, recorded before the
				// optional counter. Keys without one use HMAC-SHA1.
				if len(rest) > 0 {
					if h, ok := hashes[string(rest[0])]; ok {
						k.hash = h
						rest = rest[1:]
					}
				}
				if len(rest) == 0 {
					c.keys[name] = k
					continue
				}
				if len(rest) == 1 && len(rest[0]) == counterLen {
					_, err := strconv.ParseUint(string(rest[0]), 10, 64)
					if err == nil {
						// Valid counter.
						k.offset = offset - counterLen
						if line[len(line)-1] == '\n' {
							k.offset--
						}
						c.keys[name] = k
						continue
					}
				}
			}
		}
		log.Printf("%s:%d: malformed key", c.file, lineno)
	}
	return c
}

func (c *Keychain) list() {
	var names []string
	for name := range c.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Println(name)
	}
}

func noSpace(r rune) rune {
	if unicode.IsSpace(r) {
		return -1
	}
	return r
}

func (c *Keychain) add(name string) {
	size := 6
	if *flag7 {
		size = 7
		if *flag8 {
			log.Fatalf("cannot use -7 and -8 together")
		}
	} else if *flag8 {
		size = 8
	}

	alg := strings.ToLower(*flagHash)
	if _, ok := hashes[alg]; !ok {
		log.Fatalf("unknown hash %q: must be sha1, sha256, or sha512", *flagHash)
	}

	fmt.Fprintf(os.Stderr, "2fa key for %s: ", name)
	text, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("error reading key: %v", err)
	}
	text = strings.Map(noSpace, text)
	text += strings.Repeat("=", -len(text)&7) // pad to 8 bytes
	if _, err := decodeKey(text); err != nil {
		log.Fatalf("invalid key: %v", err)
	}

	line := fmt.Sprintf("%s %d %s", name, size, text)
	if alg != "sha1" {
		// Omitted for sha1 so that the common case stays
		// readable by keychain readers that predate -hash.
		line += " " + alg
	}
	if *flagHotp {
		line += " " + strings.Repeat("0", 20)
	}
	line += "\n"

	f, err := os.OpenFile(c.file, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		log.Fatalf("opening keychain: %v", err)
	}
	if err := f.Chmod(0600); err != nil {
		log.Fatalf("adding key: %v", err)
	}

	if _, err := f.Write([]byte(line)); err != nil {
		log.Fatalf("adding key: %v", err)
	}
	if err := f.Close(); err != nil {
		log.Fatalf("adding key: %v", err)
	}
}

func (c *Keychain) remove(name string) {
	if _, ok := c.keys[name]; !ok {
		log.Fatalf("no such key %q", name)
	}

	var buf bytes.Buffer
	for _, line := range bytes.SplitAfter(c.data, []byte("\n")) {
		f := bytes.Split(bytes.TrimSuffix(line, []byte("\n")), []byte(" "))
		if string(f[0]) == name {
			continue
		}
		buf.Write(line)
	}

	// Write the new keychain to a temporary file in the same directory
	// and rename it into place, so an interrupted removal cannot
	// truncate or corrupt the existing keychain.
	dir, base := filepath.Split(c.file)
	f, err := os.CreateTemp(dir, base)
	if err != nil {
		log.Fatalf("removing key: %v", err)
	}
	tmp := f.Name()
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		log.Fatalf("removing key: %v", err)
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		log.Fatalf("removing key: %v", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		log.Fatalf("removing key: %v", err)
	}
	if err := os.Rename(tmp, c.file); err != nil {
		_ = os.Remove(tmp)
		log.Fatalf("removing key: %v", err)
	}
}

func (c *Keychain) code(name string) string {
	k, ok := c.keys[name]
	if !ok {
		log.Fatalf("no such key %q", name)
	}
	var code int
	if k.offset != 0 {
		n, err := strconv.ParseUint(string(c.data[k.offset:k.offset+counterLen]), 10, 64)
		if err != nil {
			log.Fatalf("malformed key counter for %q (%q)", name, c.data[k.offset:k.offset+counterLen])
		}
		n++
		code = hotp(k.raw, n, k.digits, k.hash)
		f, err := os.OpenFile(c.file, os.O_RDWR, 0600)
		if err != nil {
			log.Fatalf("opening keychain: %v", err)
		}
		if _, err := f.WriteAt([]byte(fmt.Sprintf("%0*d", counterLen, n)), int64(k.offset)); err != nil {
			log.Fatalf("updating keychain: %v", err)
		}
		if err := f.Close(); err != nil {
			log.Fatalf("updating keychain: %v", err)
		}
	} else {
		// Time-based key.
		code = totp(k.raw, time.Now(), k.digits, k.hash)
	}
	return fmt.Sprintf("%0*d", k.digits, code)
}

func (c *Keychain) show(name string) {
	code := c.code(name)
	if *flagClip {
		if err := clipboard.WriteAll(code); err != nil {
			log.Printf("copying to clipboard: %v", err)
		}
	}
	fmt.Printf("%s\n", code)
}

func (c *Keychain) showAll() {
	var names []string
	width := 0
	for name, k := range c.keys {
		names = append(names, name)
		width = max(width, k.digits)
	}
	sort.Strings(names)
	for _, name := range names {
		k := c.keys[name]
		code := strings.Repeat("-", k.digits)
		if k.offset == 0 {
			code = c.code(name)
		}
		fmt.Printf("%-*s\t%s\n", width, code, name)
	}
}

func decodeKey(key string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(strings.ToUpper(key))
}

func hotp(key []byte, counter uint64, digits int, alg func() hash.Hash) int {
	h := hmac.New(alg, key)
	_ = binary.Write(h, binary.BigEndian, counter)
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	d := uint32(1)
	for i := 0; i < digits && i < 8; i++ {
		d *= 10
	}
	return int(v % d)
}

func totp(key []byte, t time.Time, digits int, alg func() hash.Hash) int {
	return hotp(key, uint64(t.UnixNano())/30e9, digits, alg)
}
