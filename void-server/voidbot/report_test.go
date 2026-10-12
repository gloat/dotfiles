package main

import (
	"strings"
	"testing"
)

func testConfig() *Config {
	return &Config{OpsChannel: "#ops", PublicChannel: "#void", PublicSkip: []string{"public/"},
		PublicURL: "https://media.gloat.ing/", MaxLines: 8}
}

// user text (comments, names, URLs) must never carry CR/LF or IRC codes into a line
func TestCleanStripsInjection(t *testing.T) {
	evil := Event{"kind": "link", "url": "https://x/\r\nPRIVMSG #ops :pwned", "sender": "a\x02b\x03" + "04c",
		"comment": "hi\nQUIT", "credit": true, "country": "US"}
	r := build(testConfig(), []Event{evil})
	if len(r.Ops) != 1 {
		t.Fatalf("want 1 line, got %d", len(r.Ops))
	}
	line := stripCodes(r.Ops[0])
	if strings.ContainsAny(r.Ops[0], "\r\n") {
		t.Fatalf("CR/LF survived: %q", r.Ops[0])
	}
	if !strings.Contains(line, "ab04c") {
		t.Fatalf("sender codes not stripped: %q", line)
	}
}

func TestUploadsGroupPerSession(t *testing.T) {
	var events []Event
	for i, name := range []string{"a.mp4", "b.mp4", "c.mp4", "d.mp4"} {
		sid := "s1"
		if i == 3 {
			sid = "s2"
		}
		events = append(events, Event{"kind": "upload", "channel": "defrag-main", "sid": sid,
			"key": "defrag-main/2026-10-11/" + sid + "/folder/" + name, "size": 1.5e9, "sender": "stupz",
			"credit": true, "comment": "comp", "country": "DE"})
	}
	r := build(testConfig(), events)
	if len(r.Ops) != 2 {
		t.Fatalf("want 2 lines (one per session), got %d: %q", len(r.Ops), r.Ops)
	}
	got := stripCodes(r.Ops[0])
	for _, want := range []string{"3 files", "4.5 GB", "folder/a.mp4", `"comp"`, "stupz"} {
		if !strings.Contains(got, want) {
			t.Errorf("line %q lacks %q", got, want)
		}
	}
}

func TestPublicOnlyNewLibraryFiles(t *testing.T) {
	r := build(testConfig(), []Event{
		{"kind": "media-add", "key": "q3/df/new run.mp4", "size": 2e9},
		{"kind": "media-add", "key": "q3/df/old.mp4", "size": 1e9, "replaced": true},
		{"kind": "media-add", "key": "public/stats/x.json", "size": 100},
		{"kind": "upload", "key": "c/d/s/secret.mp4", "size": 1, "channel": "c", "sid": "s"},
		{"kind": "key-ok", "channel": "c", "sid": "s", "ip": "1.2.3.4"},
	})
	if len(r.Public) != 1 {
		t.Fatalf("want 1 public line, got %q", r.Public)
	}
	got := stripCodes(r.Public[0])
	if !strings.Contains(got, "new run.mp4") || !strings.Contains(got, "https://media.gloat.ing/q3/df/") {
		t.Errorf("public line: %q", got)
	}
	if strings.Contains(got, "old.mp4") || strings.Contains(got, "1.2.3.4") || strings.Contains(got, "secret") {
		t.Errorf("public line leaks: %q", got)
	}
}

func TestKeyFailsSummed(t *testing.T) {
	var events []Event
	for i := 0; i < 7; i++ {
		events = append(events, Event{"kind": "key-fail", "ip": "9.9.9.9", "country": "NL"})
	}
	events = append(events, Event{"kind": "key-fail", "ip": "8.8.8.8", "country": "US"})
	r := build(testConfig(), events)
	got := stripCodes(strings.Join(r.Ops, "\n"))
	if len(r.Ops) != 1 || !strings.Contains(got, "8 failed key tries from 2 IPs") || !strings.Contains(got, "9.9.9.9 ×7") {
		t.Errorf("got %q", got)
	}
}

func TestFitAndTruncate(t *testing.T) {
	lines := make([]string, 12)
	out := fit(lines, 8, "")
	if len(out) != 8 || !strings.Contains(out[7], "+5 more") {
		t.Errorf("fit: %q", out)
	}
	long := strings.Repeat("é", 400) // 800 bytes
	cut := truncateBytes(long, maxLine)
	if len(cut) > maxLine || !strings.HasSuffix(cut, "…") || !strings.HasPrefix(cut, "é") {
		t.Errorf("truncate: %d bytes", len(cut))
	}
	if strings.ContainsRune(cut, '�') {
		t.Error("cut inside a rune")
	}
}

func TestFolderURLEncodes(t *testing.T) {
	got := folderURL("https://media.gloat.ing/", "q3/DeFRaG [x]/")
	if got != "https://media.gloat.ing/q3/DeFRaG%20%5Bx%5D/" {
		t.Errorf("got %s", got)
	}
}

// a dotfiles leak alert is one line, highlights the owner, and can't inject
func TestAlertPings(t *testing.T) {
	r := build(testConfig(), []Event{{"kind": "alert", "text": "dotfiles watch: LEAK\r\nQUIT", "by": "dotfiles-watch"}})
	if len(r.Ops) != 1 || !r.Ping {
		t.Fatalf("want 1 pinging line, got %d lines, ping %v", len(r.Ops), r.Ping)
	}
	if strings.ContainsAny(r.Ops[0], "\r\n") || !strings.Contains(stripCodes(r.Ops[0]), "dotfiles watch: LEAKQUIT") {
		t.Fatalf("bad alert line: %q", r.Ops[0])
	}
}
