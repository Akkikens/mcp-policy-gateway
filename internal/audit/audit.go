// Package audit is an append-only, hash-chained JSONL log of gateway
// decisions. Each record carries the hash of the previous one, so editing,
// reordering or deleting a record in the middle breaks verification.
// Argument values are never stored, only their SHA-256.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Genesis is the prev_hash of the first record.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Record is one audit entry.
type Record struct {
	Seq           uint64    `json:"seq"`
	Time          time.Time `json:"time"`
	Event         string    `json:"event"` // allow | deny | error
	Subject       string    `json:"subject,omitempty"`
	ClientID      string    `json:"client_id,omitempty"`
	Method        string    `json:"method,omitempty"`
	Server        string    `json:"server,omitempty"`
	Tool          string    `json:"tool,omitempty"`
	ArgsSHA256    string    `json:"args_sha256,omitempty"`
	PolicyVersion uint64    `json:"policy_version,omitempty"`
	Binding       string    `json:"binding,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	Matched       []string  `json:"matched,omitempty"`
	PrevHash      string    `json:"prev_hash"`
	Hash          string    `json:"hash"`
}

func hashRecord(r Record) (string, error) {
	r.Hash = ""
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(append([]byte(r.PrevHash+"\n"), b...))
	return hex.EncodeToString(h[:]), nil
}

// Log appends records to a file.
type Log struct {
	mu   sync.Mutex
	f    *os.File
	seq  uint64
	head string
	Now  func() time.Time
}

// Open opens (or creates) the log, verifying the existing chain first. It
// refuses to append to a chain that does not verify.
func Open(path string) (*Log, error) {
	n, head, err := VerifyFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("existing audit log does not verify: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if head == "" {
		head = Genesis
	}
	return &Log{f: f, seq: uint64(n), head: head}, nil
}

// Append writes one record, filling seq, time and the chain fields.
func (l *Log) Append(r Record) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	r.Seq = l.seq
	if l.Now != nil {
		r.Time = l.Now().UTC()
	} else {
		r.Time = time.Now().UTC()
	}
	r.PrevHash = l.head
	h, err := hashRecord(r)
	if err != nil {
		l.seq--
		return r, err
	}
	r.Hash = h
	b, _ := json.Marshal(r)
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		l.seq--
		return r, err
	}
	l.head = h
	return r, nil
}

// Head returns the latest hash. Publishing it somewhere the gateway cannot
// write (a ticket, a separate log sink) is what makes tail truncation
// detectable; the chain alone cannot detect it.
func (l *Log) Head() (uint64, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq, l.head
}

// Close closes the file.
func (l *Log) Close() error { return l.f.Close() }

// TamperError points at the first record that fails verification.
type TamperError struct {
	Line   int
	Reason string
}

func (e *TamperError) Error() string { return fmt.Sprintf("audit line %d: %s", e.Line, e.Reason) }

// VerifyFile verifies a log file and returns the record count and head hash.
func VerifyFile(path string) (int, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	return Verify(f)
}

// Verify checks sequence numbers, hashes and links of every record.
func Verify(r io.Reader) (int, string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	prev := Genesis
	n := 0
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		n++
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		var rec Record
		if err := dec.Decode(&rec); err != nil {
			return n, prev, &TamperError{Line: n, Reason: "unparseable record"}
		}
		if rec.Seq != uint64(n) {
			return n, prev, &TamperError{Line: n, Reason: fmt.Sprintf("seq %d, want %d", rec.Seq, n)}
		}
		if rec.PrevHash != prev {
			return n, prev, &TamperError{Line: n, Reason: "prev_hash does not link to the previous record"}
		}
		want, err := hashRecord(rec)
		if err != nil || want != rec.Hash {
			return n, prev, &TamperError{Line: n, Reason: "hash mismatch (record edited)"}
		}
		prev = rec.Hash
	}
	if err := sc.Err(); err != nil {
		return n, prev, err
	}
	return n, prev, nil
}
