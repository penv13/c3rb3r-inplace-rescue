package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var partialFactors = map[byte]uint64{
	10: 4, 15: 5, 20: 7, 25: 9, 30: 10, 35: 12,
	40: 14, 50: 10, 60: 20, 70: 23, 80: 27,
}

type Segment struct {
	Offset uint64
	Length uint64
}

func chacha8Block(out []byte, key []byte, nonce []byte, counter uint64) {
	constants := [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}
	var state [16]uint32
	state[0] = constants[0]
	state[1] = constants[1]
	state[2] = constants[2]
	state[3] = constants[3]
	for i := 0; i < 8; i++ {
		state[4+i] = binary.LittleEndian.Uint32(key[i*4 : (i+1)*4])
	}
	state[12] = uint32(counter & 0xffffffff)
	state[13] = uint32((counter >> 32) & 0xffffffff)
	state[14] = binary.LittleEndian.Uint32(nonce[0:4])
	state[15] = binary.LittleEndian.Uint32(nonce[4:8])

	x := state
	rot := func(v uint32, c uint) uint32 {
		return (v << c) | (v >> (32 - c))
	}
	q := func(a, b, c, d int) {
		x[a] += x[b]
		x[d] ^= x[a]
		x[d] = rot(x[d], 16)
		x[c] += x[d]
		x[b] ^= x[c]
		x[b] = rot(x[b], 12)
		x[a] += x[b]
		x[d] ^= x[a]
		x[d] = rot(x[d], 8)
		x[c] += x[d]
		x[b] ^= x[c]
		x[b] = rot(x[b], 7)
	}

	for i := 0; i < 4; i++ {
		q(0, 4, 8, 12)
		q(1, 5, 9, 13)
		q(2, 6, 10, 14)
		q(3, 7, 11, 15)
		q(0, 5, 10, 15)
		q(1, 6, 11, 12)
		q(2, 7, 8, 13)
		q(3, 4, 9, 14)
	}

	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(out[i*4:(i+1)*4], x[i]+state[i])
	}
}

func chacha8Process(data []byte, key []byte, nonce []byte, counter uint64) {
	var ks [64]byte
	numBlocks := (len(data) + 63) / 64
	for b := 0; b < numBlocks; b++ {
		chacha8Block(ks[:], key, nonce, counter+uint64(b))
		start := b * 64
		end := start + 64
		if end > len(data) {
			end = len(data)
		}
		for i := start; i < end; i++ {
			data[i] ^= ks[i-start]
		}
	}
}

func getSegments(origSize uint64, mode byte, percent byte) ([]Segment, error) {
	if mode == 0x24 {
		if percent != 0 {
			return nil, fmt.Errorf("unexpected percent for mode 0x24: %d", percent)
		}
		return []Segment{{Offset: 0, Length: origSize}}, nil
	}
	if mode == 0x26 {
		lim := uint64(1024 * 1024)
		if origSize < lim {
			lim = origSize
		}
		return []Segment{{Offset: 0, Length: lim}}, nil
	}
	if mode == 0x25 {
		factor, ok := partialFactors[percent]
		if !ok {
			return nil, fmt.Errorf("unsupported percent factor: %d", percent)
		}
		length := (origSize / 100) * factor
		count := 3
		if percent == 50 {
			count = 5
		}
		var gap uint64
		if percent == 50 {
			gap = length
		} else {
			gap = (origSize - 3*length) / 2
		}
		var segs []Segment
		for i := 0; i < count; i++ {
			segs = append(segs, Segment{
				Offset: uint64(i) * (length + gap),
				Length: length,
			})
		}
		return segs, nil
	}
	return nil, fmt.Errorf("unsupported mode: 0x%02x", mode)
}

func decryptFileInPlace(path string, masterKey []byte, dryRun bool) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if !fi.Mode().IsRegular() {
		return 0, fmt.Errorf("not a regular file")
	}
	if fi.Size() < 588 {
		return 0, fmt.Errorf("file too small (%d bytes)", fi.Size())
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return 0, fmt.Errorf("open failed: %w", err)
	}
	defer f.Close()

	footer := make([]byte, 588)
	if _, err := f.ReadAt(footer, fi.Size()-588); err != nil {
		return 0, fmt.Errorf("read footer failed: %w", err)
	}

	// Unwrap session key record using AES-256-CBC
	block, err := aes.NewCipher(masterKey[16:])
	if err != nil {
		return 0, err
	}
	cbc := cipher.NewCBCDecrypter(block, masterKey[:16])
	rec := make([]byte, 48)
	copy(rec, footer[:48])
	cbc.CryptBlocks(rec, rec)

	// Nonce validation
	if !bytes.Equal(rec[32:40], rec[40:48]) {
		return 0, fmt.Errorf("nonce mismatch: %x != %x", rec[32:40], rec[40:48])
	}
	fileKey := rec[:32]
	fileNonce := rec[32:40]

	mode := footer[572]
	percent := footer[573]
	cryptoMode := footer[574]
	origSize := binary.LittleEndian.Uint64(footer[580:588])

	if cryptoMode != 0x20 {
		return 0, fmt.Errorf("unsupported cryptoMode: 0x%02x", cryptoMode)
	}
	if origSize != uint64(fi.Size()-588) {
		return 0, fmt.Errorf("size mismatch: origSize=%d, file_size-588=%d", origSize, fi.Size()-588)
	}

	segs, err := getSegments(origSize, mode, percent)
	if err != nil {
		return 0, fmt.Errorf("getSegments error: %w", err)
	}

	if dryRun {
		return origSize, nil
	}

	counter := uint64(0)
	chunkLimit := uint64(5 * 1024 * 1024) // 5MB buffer

	buf := make([]byte, chunkLimit)
	for _, seg := range segs {
		pos := seg.Offset
		rem := seg.Length
		for rem > 0 {
			take := rem
			if take > chunkLimit {
				take = chunkLimit
			}
			chunk := buf[:take]
			if _, err := f.ReadAt(chunk, int64(pos)); err != nil {
				return 0, fmt.Errorf("read at %d failed: %w", pos, err)
			}
			chacha8Process(chunk, fileKey, fileNonce, counter)
			counter += (take + 63) / 64
			if _, err := f.WriteAt(chunk, int64(pos)); err != nil {
				return 0, fmt.Errorf("write at %d failed: %w", pos, err)
			}
			pos += take
			rem -= take
		}
	}

	// In-place truncate: remove 588 bytes footer
	if err := f.Truncate(int64(origSize)); err != nil {
		return 0, fmt.Errorf("truncate failed: %w", err)
	}
	if err := f.Sync(); err != nil {
		return 0, fmt.Errorf("sync failed: %w", err)
	}
	_ = f.Close()

	// Rename back to original filename
	targetPath := strings.TrimSuffix(path, ".L0CK3D")
	if path != targetPath {
		if err := os.Rename(path, targetPath); err != nil {
			return 0, fmt.Errorf("rename failed: %w", err)
		}
	}

	return origSize, nil
}

func main() {
	targetDir := flag.String("dir", "", "Directory to scan and decrypt recursively")
	targetFile := flag.String("file", "", "Single .L0CK3D file to decrypt")
	targetList := flag.String("list", "", "File containing list of locked file paths (one per line)")
	masterHex := flag.String("key", "", "48-byte master key in hex (96 hex characters, required)")
	dryRun := flag.Bool("dry-run", false, "Simulate decryption without modifying files")
	cleanNotes := flag.Bool("clean-notes", true, "Automatically delete ransom notes (read-me3.txt) in scanned directories")
	workers := flag.Int("workers", 8, "Number of concurrent decryptor workers")
	verbose := flag.Bool("v", false, "Verbose output for each processed file")
	flag.Parse()

	if *masterHex == "" {
		fmt.Fprintf(os.Stderr, "Error: --key is required (48 bytes / 96 hex characters).\n")
		flag.Usage()
		os.Exit(1)
	}

	masterKey, err := hex.DecodeString(*masterHex)
	if err != nil || len(masterKey) != 48 {
		fmt.Fprintf(os.Stderr, "Error: invalid master key (must be exactly 48 bytes / 96 hex characters)\n")
		os.Exit(1)
	}

	var targets []string
	var notePaths []string

	if *targetFile != "" {
		targets = append(targets, *targetFile)
	} else if *targetList != "" {
		f, err := os.Open(*targetList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Open list failed: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				targets = append(targets, line)
			}
		}
	} else if *targetDir != "" {
		err = filepath.Walk(*targetDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				note := filepath.Join(path, "read-me3.txt")
				if _, err := os.Stat(note); err == nil {
					notePaths = append(notePaths, note)
				}
			} else if strings.HasSuffix(info.Name(), ".L0CK3D") {
				targets = append(targets, path)
			}
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Walk error: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Error: either --dir, --file, or --list must be specified\n")
		flag.Usage()
		os.Exit(1)
	}

	fmt.Printf("[*] Loaded %d target file(s) to process (Workers: %d, DryRun: %v).\n", len(targets), *workers, *dryRun)
	if len(targets) == 0 {
		return
	}

	var succeeded int32
	var failed int32
	var totalBytes uint64
	tTotal := time.Now()

	ch := make(chan string, 1024)
	var wg sync.WaitGroup

	numWorkers := *workers
	if numWorkers < 1 {
		numWorkers = 1
	}

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range ch {
				t0 := time.Now()
				sz, err := decryptFileInPlace(path, masterKey, *dryRun)
				if err != nil {
					fmt.Printf("[ERROR] %s: %v\n", filepath.Base(path), err)
					atomic.AddInt32(&failed, 1)
				} else {
					atomic.AddInt32(&succeeded, 1)
					atomic.AddUint64(&totalBytes, sz)
					cur := atomic.LoadInt32(&succeeded)
					if *verbose || cur%200 == 0 || cur == int32(len(targets)) {
						fmt.Printf("[%d/%d] Restored (%s): %s (%.2f MB)\n",
							cur, len(targets), time.Since(t0).Round(time.Millisecond), filepath.Base(path), float64(sz)/(1024*1024))
					}
				}
			}
		}()
	}

	for _, target := range targets {
		ch <- target
	}
	close(ch)
	wg.Wait()

	// Clean ransom notes if requested and not in dry-run
	notesRemoved := 0
	if *cleanNotes && !*dryRun {
		for _, note := range notePaths {
			if err := os.Remove(note); err == nil {
				notesRemoved++
			}
		}
	}

	fmt.Printf("\n--- In-Place Recovery Summary ---\n")
	fmt.Printf("Total files scanned: %d\n", len(targets))
	fmt.Printf("Successfully decrypted: %d\n", succeeded)
	fmt.Printf("Failed:                %d\n", failed)
	fmt.Printf("Ransom notes removed:  %d\n", notesRemoved)
	fmt.Printf("Total data restored:   %.2f GB\n", float64(totalBytes)/(1024*1024*1024))
	fmt.Printf("Total elapsed time:    %s\n", time.Since(tTotal).Round(time.Millisecond))
}
