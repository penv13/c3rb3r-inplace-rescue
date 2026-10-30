package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	dumpPath := flag.String("dump", "", "Path to process memory dump file (e.g. mem_dump.bin)")
	targetHex := flag.String("target", "", "Last 48 bytes of any .L0CK3D file footer in hex")
	step := flag.Int("step", 1, "Scan sliding step in bytes (1 for thorough, 4/8/16 for aligned)")
	workers := flag.Int("workers", runtime.NumCPU(), "Number of parallel workers")
	flag.Parse()

	if *dumpPath == "" || *targetHex == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -dump <mem_dump.bin> -target <last_48_bytes_hex> [-step 1] [-workers %d]\n", os.Args[0], runtime.NumCPU())
		os.Exit(1)
	}

	targetCT, err := hex.DecodeString(*targetHex)
	if err != nil || len(targetCT) != 48 {
		fmt.Fprintf(os.Stderr, "Error: target must be 48 bytes hex (96 hex characters). Got %d bytes\n", len(targetCT))
		os.Exit(1)
	}

	f, err := os.Open(*dumpPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening dump file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error stating dump file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Loading memory dump: %s (%.2f MB)\n", *dumpPath, float64(fi.Size())/(1024*1024))
	mem, err := io.ReadAll(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading dump file: %v\n", err)
		os.Exit(1)
	}

	totalLen := len(mem)
	if totalLen < 48 {
		fmt.Fprintf(os.Stderr, "Dump file too small (%d bytes)\n", totalLen)
		os.Exit(1)
	}

	maxOffset := totalLen - 48
	stepSize := *step
	numWorkers := *workers
	if numWorkers < 1 {
		numWorkers = 1
	}

	fmt.Printf("[*] Scanning candidates with step=%d, workers=%d...\n", stepSize, numWorkers)
	tStart := time.Now()

	var foundCount int32
	var wg sync.WaitGroup
	chunkSize := (maxOffset/stepSize + numWorkers - 1) / numWorkers

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		startIdx := w * chunkSize
		endIdx := startIdx + chunkSize
		go func(sIdx, eIdx int) {
			defer wg.Done()
			pt := make([]byte, 48)

			for idx := sIdx; idx < eIdx; idx++ {
				offset := idx * stepSize
				if offset > maxOffset {
					break
				}

				// Skip regions containing all zeros
				cand := mem[offset : offset+48]
				if cand[0] == 0 && cand[1] == 0 && cand[2] == 0 && cand[3] == 0 {
					continue
				}
				if cand[16] == 0 && cand[17] == 0 && cand[18] == 0 && cand[19] == 0 {
					continue
				}

				iv := cand[:16]
				key := cand[16:48]

				block, err := aes.NewCipher(key)
				if err != nil {
					continue
				}

				cbc := cipher.NewCBCDecrypter(block, iv)
				cbc.CryptBlocks(pt, targetCT)

				// Core signature: Nonce repeated at bytes [32..40] and [40..48]
				if bytes.Equal(pt[32:40], pt[40:48]) {
					atomic.AddInt32(&foundCount, 1)
					fmt.Printf("\n[SUCCESS] Master Key Found at offset 0x%x (%d)!\n", offset, offset)
					fmt.Printf("  Master IV (16 bytes):  %s\n", hex.EncodeToString(iv))
					fmt.Printf("  Master Key (32 bytes): %s\n", hex.EncodeToString(key))
					fmt.Printf("  Master Material (48B): %s\n", hex.EncodeToString(cand))
					fmt.Printf("  Decrypted Nonce (8B):  %s\n\n", hex.EncodeToString(pt[32:40]))
				}
			}
		}(startIdx, endIdx)
	}

	wg.Wait()
	fmt.Printf("[*] Scan completed in %s. Matches found: %d\n", time.Since(tStart).Round(time.Millisecond), foundCount)
}
