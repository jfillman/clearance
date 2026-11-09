package verify

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// The local note of checkpoints seen: the weak-witness behaviour. A verifier that keeps what it has seen can say
// that a later packet's checkpoint contradicts an earlier one (the same size with a different root: a fork shown
// to different readers) even when the log and its witnesses are both honest-looking in the packet itself.
//
// It records a checkpoint only after the log's signature checked under keys the user supplied, and only when
// nothing failed, so a packet vouching for its own keys cannot write into the note.

const seenSchema = "clearance.verify-seen/v1"

type seenFile struct {
	Schema string                 `json:"schema"`
	Logs   map[string][]seenEntry `json:"logs"` // by origin
}

type seenEntry struct {
	Size    int64  `json:"size"`
	Root    string `json:"root"`
	Seen    string `json:"first_seen"`
	Witness bool   `json:"witnessed"`
}

func (c *ctx) seenCheck() {
	path := c.opts.SeenFile
	if path == "" {
		return
	}
	chk := Check{Name: "checkpoints seen before (local note)"}
	if c.cp == nil {
		chk.Status, chk.Detail = NotChecked, "this packet has no checkpoint to compare or record"
		c.rep.add(chk)
		return
	}
	var f seenFile
	switch raw, err := os.ReadFile(path); {
	case errors.Is(err, os.ErrNotExist):
		f = seenFile{Schema: seenSchema, Logs: map[string][]seenEntry{}}
	case err != nil:
		chk.Status, chk.Detail = Fail, "the note "+path+" cannot be read: "+err.Error()
		c.rep.add(chk)
		return
	default:
		if err := json.Unmarshal(raw, &f); err != nil || f.Schema != seenSchema {
			chk.Status, chk.Detail = Fail, "the note "+path+" is not a "+seenSchema+" file; move it aside rather than have it overwritten"
			c.rep.add(chk)
			return
		}
		if f.Logs == nil {
			f.Logs = map[string][]seenEntry{}
		}
	}
	cp := c.cp
	root := hex.EncodeToString(cp.root)
	var bad, info []string
	known := false
	var maxSize int64
	for _, e := range f.Logs[cp.origin] {
		if e.Size > maxSize {
			maxSize = e.Size
		}
		if e.Size == cp.size {
			known = true
			if e.Root != root {
				bad = append(bad, fmt.Sprintf("FORK: you have seen log %q at %d records with root %s (first seen %s); this packet's checkpoint is also %d records and its root is %s. "+
					"A log shows one tree of a given size to everyone; one of the two is not the log's.", cp.origin, e.Size, short8(e.Root), e.Seen, e.Size, short8(root)))
			}
		}
	}
	switch {
	case len(bad) > 0:
	case known:
		info = append(info, fmt.Sprintf("seen before: log %q at %d records, same root", cp.origin, cp.size))
	case maxSize == 0:
		info = append(info, fmt.Sprintf("first checkpoint of log %q this note has seen (%d records)", cp.origin, cp.size))
	case cp.size < maxSize:
		info = append(info, fmt.Sprintf("older than a checkpoint you have seen (%d records, this one %d): not a failure, but nothing here can show the %d-record tree extends this one", maxSize, cp.size, maxSize))
	default:
		info = append(info, fmt.Sprintf("newer than the last checkpoint you saw (%d records, this one %d). The packet carries no consistency proof, so this verifier cannot show it extends the earlier tree; "+
			"a witness cosignature is what does", maxSize, cp.size))
	}
	chk.Findings = append(bad, info...)
	if len(bad) > 0 {
		chk.Status, chk.Detail = Fail, "this checkpoint contradicts one you have seen"
		c.rep.add(chk)
		return
	}
	chk.Status, chk.Detail = Pass, "no contradiction with the checkpoints in "+path
	// Record it, only when it is worth believing.
	switch {
	case c.cpTrust != trustSupplied:
		chk.Findings = append(chk.Findings, "not recorded: its signature was not checked under log keys you supplied")
	case c.rep.Failed():
		chk.Findings = append(chk.Findings, "not recorded: the packet failed other checks")
	case known:
	default:
		f.Logs[cp.origin] = append(f.Logs[cp.origin], seenEntry{Size: cp.size, Root: root, Seen: c.opts.Now().UTC().Format(time.RFC3339), Witness: len(cp.cosigned) > 0})
		sort.Slice(f.Logs[cp.origin], func(i, j int) bool { return f.Logs[cp.origin][i].Size < f.Logs[cp.origin][j].Size })
		if err := writeSeen(path, f); err != nil {
			chk.Findings = append(chk.Findings, "not recorded: "+err.Error())
		} else {
			chk.Findings = append(chk.Findings, "recorded in "+path)
		}
	}
	c.rep.add(chk)
}

func writeSeen(path string, f seenFile) error {
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".verify-seen-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // gone after the rename
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
