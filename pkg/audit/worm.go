package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// WORMDispatcher writes the audit chain to an append-only file.
//
// "WORM" here means the file is opened O_APPEND so writes can only add
// to the tail. Operators are expected to mount the directory on
// hardware-WORM media (immutable S3 prefix, write-once tape, or a
// filesystem with chattr +a) for the integrity guarantee — this struct
// supplies the chain itself but does not enforce hardware immutability.
//
// File format: one JSON object per line (NDJSON). Each line is a sealed
// Event. Recovery on startup re-reads the tail to recover the head Seq
// and Hash; corruption is detected by VerifyChain.
type WORMDispatcher struct {
	path string
	mu   sync.Mutex
	f    *os.File
	w    *bufio.Writer
	seq  uint64
	head string
}

// NewWORMDispatcher opens path (creating parent directories as needed)
// and replays it to recover the chain head.
func NewWORMDispatcher(path string) (*WORMDispatcher, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("audit/worm: mkdir: %w", err)
	}

	d := &WORMDispatcher{path: path}
	if err := d.replay(); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("audit/worm: open: %w", err)
	}
	d.f = f
	d.w = bufio.NewWriterSize(f, 64<<10)
	return d, nil
}

// replay walks the existing file (if any) and recovers seq + head. It
// also verifies the chain — a corrupt log refuses to open.
func (d *WORMDispatcher) replay() error {
	f, err := os.Open(d.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("audit/worm: replay open: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20) // up to 16 MiB per line
	prev := ""
	var seq uint64
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return fmt.Errorf("audit/worm: replay parse seq=%d: %w", seq, err)
		}
		if ev.PrevHash != prev {
			return fmt.Errorf("audit/worm: replay chain break at seq=%d (prev=%q expected=%q)", ev.Seq, ev.PrevHash, prev)
		}
		want := ev.Hash
		ev.Hash = ""
		got, err := ev.ComputeHash()
		if err != nil {
			return fmt.Errorf("audit/worm: replay hash seq=%d: %w", ev.Seq, err)
		}
		if got != want {
			return fmt.Errorf("audit/worm: replay tampered at seq=%d (stored=%q recomputed=%q)", ev.Seq, want, got)
		}
		prev = want
		seq = ev.Seq + 1
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("audit/worm: replay scan: %w", err)
	}
	d.seq = seq
	d.head = prev
	return nil
}

func (d *WORMDispatcher) Append(_ context.Context, ev *Event) (*Event, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	sealed, err := ev.Seal(d.seq, d.head)
	if err != nil {
		return nil, fmt.Errorf("audit/worm: seal: %w", err)
	}
	line, err := json.Marshal(sealed)
	if err != nil {
		return nil, fmt.Errorf("audit/worm: marshal: %w", err)
	}
	if _, err := d.w.Write(line); err != nil {
		return nil, fmt.Errorf("audit/worm: write: %w", err)
	}
	if err := d.w.WriteByte('\n'); err != nil {
		return nil, fmt.Errorf("audit/worm: write newline: %w", err)
	}
	if err := d.w.Flush(); err != nil {
		return nil, fmt.Errorf("audit/worm: flush: %w", err)
	}
	if err := d.f.Sync(); err != nil {
		return nil, fmt.Errorf("audit/worm: fsync: %w", err)
	}
	d.seq = sealed.Seq + 1
	d.head = sealed.Hash
	return sealed, nil
}

func (d *WORMDispatcher) VerifyHead(_ context.Context) (uint64, string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seq == 0 {
		return 0, "", nil
	}
	return d.seq - 1, d.head, nil
}

func (d *WORMDispatcher) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.w != nil {
		_ = d.w.Flush()
	}
	if d.f != nil {
		err := d.f.Close()
		d.f = nil
		return err
	}
	return nil
}
