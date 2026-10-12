package main

// sysinfo: every 30 s, a small public JSON file with the server's numbers for the site's terminal
// (fastfetch, top, uptime, free, df; js/void-term*.js). OpenResty serves the file as is
// (location = /void/sysinfo, notes/terminal-plan.md), so nothing new listens on the VPS.
// Public on purpose: load, memory, disk, kernel, which services run, IRC users, storage. No IPs, no names.

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ergochat/irc-go/ircmsg"
)

const sysinfoEvery = 30 * time.Second

type SysInfo struct {
	At       int64           `json:"at"`
	OS       string          `json:"os"`
	Kernel   string          `json:"kernel"`
	UptimeS  float64         `json:"uptime_s"`
	Load     [3]float64      `json:"load"`
	Procs    int             `json:"procs"`
	CPU      CPUInfo         `json:"cpu"`
	Mem      MemInfo         `json:"mem"`
	Disk     DiskInfo        `json:"disk"`
	Net      *NetInfo        `json:"net,omitempty"`
	Services map[string]bool `json:"services"`
	IRC      *IRCInfo        `json:"irc,omitempty"`
	R2       *R2Info         `json:"r2,omitempty"`
}

type CPUInfo struct {
	Model string `json:"model"`
	Cores int    `json:"cores"`
}

type MemInfo struct {
	Total     uint64 `json:"total"`
	Available uint64 `json:"available"`
	SwapTotal uint64 `json:"swap_total"`
	SwapFree  uint64 `json:"swap_free"`
}

type DiskInfo struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

type NetInfo struct {
	RX uint64 `json:"rx"`
	TX uint64 `json:"tx"`
}

type IRCInfo struct {
	Users int `json:"users"`
}

type R2Info struct {
	Used   float64 `json:"used"`
	Budget float64 `json:"budget"`
	Paused bool    `json:"paused"`
}

// what the rest of the bot learns along the way (the Worker poll, LUSERS replies)
type sysShared struct {
	mu    sync.Mutex
	r2    *R2Info
	users int
	seen  time.Time // when users was last set
}

func (s *sysShared) setR2(p *EventPage) {
	if p == nil || p.Budget <= 0 {
		return
	}
	s.mu.Lock()
	s.r2 = &R2Info{Used: p.Used, Budget: p.Budget, Paused: p.Paused}
	s.mu.Unlock()
}

// 266 RPL_GLOBALUSERS: "<me> <current> <max> :Current global users ..." (some servers only put the
// numbers in the text: "Current global users: 5, max: 9")
var usersInText = regexp.MustCompile(`(?i)users:?\s+(\d+)`)

func parseGlobalUsers(e ircmsg.Message) (int, bool) {
	if len(e.Params) >= 3 {
		if n, err := strconv.Atoi(e.Params[1]); err == nil {
			return n, true
		}
	}
	if len(e.Params) > 0 {
		if m := usersInText.FindStringSubmatch(e.Params[len(e.Params)-1]); m != nil {
			n, _ := strconv.Atoi(m[1])
			return n, true
		}
	}
	return 0, false
}

func (b *Bot) onGlobalUsers(e ircmsg.Message) {
	if n, ok := parseGlobalUsers(e); ok {
		b.sys.mu.Lock()
		b.sys.users = n
		b.sys.seen = time.Now()
		b.sys.mu.Unlock()
	}
}

func (b *Bot) sysinfoLoop() {
	if b.cfg.SysinfoFile == "" {
		return
	}
	var lastErr time.Time
	for {
		if b.irc.Connected() {
			b.irc.Send("LUSERS") // the 266 reply lands in onGlobalUsers before the next write
		}
		info := collectSysinfo("/")
		b.sys.mu.Lock()
		if b.sys.r2 != nil {
			r := *b.sys.r2
			info.R2 = &r
		}
		if time.Since(b.sys.seen) < 3*sysinfoEvery {
			info.IRC = &IRCInfo{Users: b.sys.users}
		}
		b.sys.mu.Unlock()
		if err := writeJSONAtomic(b.cfg.SysinfoFile, info); err != nil && time.Since(lastErr) > time.Hour {
			log.Printf("sysinfo: %v", err) // at most once an hour (a missing directory would repeat forever)
			lastErr = time.Now()
		}
		time.Sleep(sysinfoEvery)
	}
}

// writeJSONAtomic writes a temp file next to the target and renames it: nginx never reads half a file
func writeJSONAtomic(path string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sysinfo-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func collectSysinfo(root string) *SysInfo {
	info := &SysInfo{At: time.Now().Unix(), Services: map[string]bool{}}
	info.OS = osName() + " " + archName()
	info.Kernel = strings.TrimSpace(readFile("/proc/sys/kernel/osrelease"))
	if f := strings.Fields(readFile("/proc/uptime")); len(f) > 0 {
		info.UptimeS, _ = strconv.ParseFloat(f[0], 64)
	}
	info.Load, info.Procs = parseLoadavg(readFile("/proc/loadavg"))
	info.CPU = parseCPUInfo(readFile("/proc/cpuinfo"))
	info.Mem = parseMeminfo(readFile("/proc/meminfo"))
	var st syscall.Statfs_t
	if syscall.Statfs(root, &st) == nil {
		bs := uint64(st.Bsize)
		info.Disk = DiskInfo{Total: st.Blocks * bs, Used: (st.Blocks - st.Bfree) * bs}
	}
	if rx, tx, ok := parseNetDev(readFile("/proc/net/dev")); ok {
		info.Net = &NetInfo{RX: rx, TX: tx}
	}
	running := processNames()
	for label, comm := range map[string]string{"openresty": "nginx", "ergo": "ergo", "fail2ban": "fail2ban-server", "sshd": "sshd"} {
		info.Services[label] = running[comm]
	}
	info.Services["voidbot"] = true
	return info
}

func readFile(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(raw)
}

func osName() string {
	sc := bufio.NewScanner(strings.NewReader(readFile("/etc/os-release")))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return "Linux"
}

func archName() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	}
	return runtime.GOARCH
}

// "0.00 0.01 0.05 1/123 4567" -> loads, 123
func parseLoadavg(s string) ([3]float64, int) {
	var load [3]float64
	f := strings.Fields(s)
	for i := 0; i < 3 && i < len(f); i++ {
		load[i], _ = strconv.ParseFloat(f[i], 64)
	}
	procs := 0
	if len(f) > 3 {
		if _, total, ok := strings.Cut(f[3], "/"); ok {
			procs, _ = strconv.Atoi(total)
		}
	}
	return load, procs
}

func parseCPUInfo(s string) CPUInfo {
	var c CPUInfo
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "processor":
			c.Cores++
		case "model name":
			if c.Model == "" {
				c.Model = strings.Join(strings.Fields(v), " ")
			}
		}
	}
	return c
}

// /proc/meminfo is in kB
func parseMeminfo(s string) MemInfo {
	var m MemInfo
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		n, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			m.Total = n * 1024
		case "MemAvailable:":
			m.Available = n * 1024
		case "SwapTotal:":
			m.SwapTotal = n * 1024
		case "SwapFree:":
			m.SwapFree = n * 1024
		}
	}
	return m
}

// bytes received/sent since boot, every interface except loopback
func parseNetDev(s string) (rx, tx uint64, ok bool) {
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		name, rest, found := strings.Cut(sc.Text(), ":")
		if !found || strings.TrimSpace(name) == "lo" {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		r, err1 := strconv.ParseUint(f[0], 10, 64)
		t, err2 := strconv.ParseUint(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		rx += r
		tx += t
		ok = true
	}
	return rx, tx, ok
}

// the comm name of every process (world-readable in /proc unless it's mounted with hidepid)
func processNames() map[string]bool {
	names := map[string]bool{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return names
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		if comm := strings.TrimSpace(readFile("/proc/" + e.Name() + "/comm")); comm != "" {
			names[comm] = true
		}
	}
	return names
}
