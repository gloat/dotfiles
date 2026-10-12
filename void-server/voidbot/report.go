package main

import (
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

// IRC formatting codes (shown as bold / colors by gamja and most clients)
const (
	bold  = "\x02"
	reset = "\x0f"
)

func color(n int, s string) string { return fmt.Sprintf("\x03%02d%s\x03", n, s) }

const (
	cGreen  = 3
	cRed    = 4
	cBrown  = 5
	cOrange = 7
	cYellow = 8
	cTeal   = 10
	cCyan   = 11
	cGrey   = 14
)

// Report is one poll's worth of lines for each channel.
type Report struct {
	Ops, Public []string
	Ping        bool // something the owner should see now (highlight)
}

// clean strips control characters (CR/LF above all: user text must never
// become a second IRC command) and IRC formatting codes from user-supplied text.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// clip shortens to at most n runes, with an ellipsis
func clip(s string, n int) string {
	s = clean(s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

func size(b float64) string {
	switch {
	case b >= 1e12:
		return fmt.Sprintf("%.2f TB", b/1e12)
	case b >= 1e9:
		return fmt.Sprintf("%.1f GB", b/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.1f MB", b/1e6)
	case b >= 1e3:
		return fmt.Sprintf("%.0f KB", b/1e3)
	}
	return fmt.Sprintf("%.0f B", b)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// names: "a, b, c +4 more"
func names(list []string, show int) string {
	if len(list) <= show {
		return strings.Join(list, ", ")
	}
	return strings.Join(list[:show], ", ") + fmt.Sprintf(" +%d more", len(list)-show)
}

// browser: "Firefox/Windows" from a user agent, good enough to tell visitors apart
func browser(ua string) string {
	b := "?"
	for _, p := range [][2]string{{"Firefox/", "Firefox"}, {"Edg/", "Edge"}, {"OPR/", "Opera"}, {"Chrome/", "Chrome"}, {"Safari/", "Safari"}, {"curl/", "curl"}} {
		if strings.Contains(ua, p[0]) {
			b = p[1]
			break
		}
	}
	for _, p := range [][2]string{{"Android", "Android"}, {"iPhone", "iPhone"}, {"iPad", "iPad"}, {"Windows", "Windows"}, {"Mac OS", "Mac"}, {"Linux", "Linux"}} {
		if strings.Contains(ua, p[0]) {
			return b + "/" + p[1]
		}
	}
	return b
}

func where(e Event) string {
	parts := []string{}
	for _, k := range []string{"country", "city"} {
		if v := clean(e.str(k)); v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, " ")
}

// fileName: the part of an incoming key after <channel>/<day>/<sid>/
func fileName(key string) string {
	parts := strings.SplitN(key, "/", 4)
	if len(parts) == 4 {
		return clean(parts[3])
	}
	return clean(path.Base(key))
}

func folderOf(key string) string {
	if dir := path.Dir(key); dir != "." {
		return dir + "/"
	}
	return ""
}

// folderURL: the public listing of an R2 folder, each segment percent-encoded
func folderURL(base, folder string) string {
	segs := strings.Split(strings.TrimSuffix(folder, "/"), "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.TrimSuffix(base, "/") + "/" + strings.Join(segs, "/") + "/"
}

func sender(e Event) string {
	s := clip(e.str("sender"), 32)
	if s == "" {
		s = "?"
	}
	if !e.flag("credit") {
		s += " (anon)"
	}
	return s
}

// group keeps first-seen order of the keys
type group[T any] struct {
	order []string
	items map[string][]T
}

func (g *group[T]) add(key string, v T) {
	if g.items == nil {
		g.items = map[string][]T{}
	}
	if _, ok := g.items[key]; !ok {
		g.order = append(g.order, key)
	}
	g.items[key] = append(g.items[key], v)
}

// build turns one page of events into channel lines. Uploads, failures and
// library changes are summed up per session / folder, so a 300-file folder
// is one line, not 300.
func build(c *Config, events []Event) Report {
	var r Report
	var uploads, rejected, refused, added, removed group[Event]
	var fails []Event

	for _, e := range events {
		switch e.kind() {
		case "key-ok":
			r.Ops = append(r.Ops, fmt.Sprintf("%s operator in · %s · %s · %s %s · %s · %s",
				color(cGreen, "🔑"), bold+clean(e.str("channel"))+reset, short(e.str("sid")),
				clean(e.str("ip")), where(e), clip(e.str("isp"), 40), browser(e.str("ua"))))
		case "key-fail":
			fails = append(fails, e)
		case "link":
			line := fmt.Sprintf("%s link from %s %s: %s", color(cCyan, "🔗"), bold+sender(e)+reset,
				color(cGrey, "("+where(e)+")"), clip(e.str("url"), 300))
			if t := clip(e.str("title"), 80); t != "" {
				line += ` "` + t + `"`
			}
			if cm := clip(e.str("comment"), 160); cm != "" {
				line += " · " + cm
			}
			r.Ops = append(r.Ops, line)
		case "upload":
			uploads.add(e.str("channel")+" "+e.str("sid"), e)
		case "upload-rejected":
			rejected.add(e.str("error"), e)
		case "upload-refused":
			refused.add(e.str("error"), e)
			if e.str("error") == "pool" {
				r.Ping = true
			}
		case "pause":
			r.Ops = append(r.Ops, fmt.Sprintf("%s uploads + links %s (by %s)", color(cOrange, "⏸"), bold+"paused"+reset, clean(e.str("by"))))
		case "resume":
			r.Ops = append(r.Ops, fmt.Sprintf("%s uploads + links %s (by %s)", color(cGreen, "▶"), bold+"open"+reset, clean(e.str("by"))))
		case "alert":
			r.Ops = append(r.Ops, fmt.Sprintf("%s %s %s", color(cRed, "🚨"), bold+clip(e.str("text"), 400)+reset,
				color(cGrey, "("+clean(e.str("by"))+")")))
			r.Ping = true
		case "media-add":
			added.add(folderOf(e.str("key")), e)
		case "media-rm":
			removed.add(folderOf(e.str("key")), e)
		}
	}

	if len(fails) > 0 {
		perIP := map[string]int{}
		countries := map[string]int{}
		for _, e := range fails {
			perIP[clean(e.str("ip"))]++
			countries[clean(e.str("country"))]++
		}
		line := fmt.Sprintf("%s %s from %s", color(cRed, "✗"), plural(len(fails), "failed key try", "failed key tries"),
			plural(len(perIP), "IP", "IPs"))
		line += " " + color(cGrey, "("+tally(countries)+")")
		if ip, n := top(perIP); n >= 5 {
			line += fmt.Sprintf(" · %s ×%d", ip, n)
		}
		r.Ops = append(r.Ops, line)
	}

	for _, k := range uploads.order {
		list := uploads.items[k]
		var total float64
		files := []string{}
		comments := map[string]bool{}
		for _, e := range list {
			total += e.num("size")
			files = append(files, fileName(e.str("key")))
			if cm := clip(e.str("comment"), 120); cm != "" {
				comments[cm] = true
			}
		}
		first := list[0]
		line := fmt.Sprintf("%s %s · %s %s: %s, %s — %s", color(cTeal, "📦"), clean(first.str("channel")),
			bold+sender(first)+reset, color(cGrey, "("+clean(first.str("country"))+")"),
			plural(len(list), "file", "files"), size(total), names(files, 3))
		if len(comments) == 1 {
			for cm := range comments {
				line += ` · "` + cm + `"`
			}
		}
		r.Ops = append(r.Ops, line)
	}
	for _, k := range rejected.order {
		files := []string{}
		for _, e := range rejected.items[k] {
			files = append(files, fileName(e.str("key")))
		}
		r.Ops = append(r.Ops, fmt.Sprintf("%s rejected (%s check): %s", color(cRed, "⛔"), clean(k), names(files, 4)))
	}
	for _, k := range refused.order {
		list := refused.items[k]
		files := []string{}
		for _, e := range list {
			files = append(files, clip(e.str("name"), 60))
		}
		why := map[string]string{"type": "file type", "size": "too big", "paused": "paused", "day": "daily cap",
			"pool": bold + "HARD STOP: storage budget full" + reset}[k]
		if why == "" {
			why = clean(k)
		}
		r.Ops = append(r.Ops, fmt.Sprintf("%s refused (%s): %s %s", color(cOrange, "⚠"), why,
			plural(len(list), "upload", "uploads"), color(cGrey, "("+names(files, 3)+")")))
	}

	for _, folder := range added.order {
		list := added.items[folder]
		var total float64
		files, fresh := []string{}, []string{}
		replaced := 0
		for _, e := range list {
			total += e.num("size")
			name := clean(path.Base(e.str("key")))
			files = append(files, name)
			if e.flag("replaced") {
				replaced++
			} else {
				fresh = append(fresh, name)
			}
		}
		line := fmt.Sprintf("%s library %s%s (%s): %s", color(cGreen, "+"), bold+"+"+fmt.Sprint(len(list))+reset,
			" in "+displayFolder(folder), size(total), names(files, 3))
		if replaced > 0 {
			line += color(cGrey, fmt.Sprintf(" (%d replaced)", replaced))
		}
		r.Ops = append(r.Ops, line)
		if c.PublicChannel != "" && len(fresh) > 0 && !skipPublic(c, folder) {
			r.Public = append(r.Public, publicLine(c, folder, list, fresh))
		}
	}
	for _, folder := range removed.order {
		files := []string{}
		for _, e := range removed.items[folder] {
			files = append(files, clean(path.Base(e.str("key"))))
		}
		r.Ops = append(r.Ops, fmt.Sprintf("%s library −%d in %s: %s", color(cBrown, "−"), len(files),
			displayFolder(folder), names(files, 3)))
	}
	return r
}

func displayFolder(folder string) string {
	if folder == "" {
		return "/"
	}
	return clean(folder)
}

func skipPublic(c *Config, folder string) bool {
	for _, p := range c.PublicSkip {
		if p != "" && strings.HasPrefix(folder, p) {
			return true
		}
	}
	return false
}

// publicLine: "new in q3/df/: a.mp4 (1.2 GB) → https://media.gloat.ing/q3/df/"
func publicLine(c *Config, folder string, list []Event, fresh []string) string {
	var total float64
	for _, e := range list {
		if !e.flag("replaced") {
			total += e.num("size")
		}
	}
	link := folderURL(c.PublicURL, folder)
	if len(fresh) == 1 {
		return fmt.Sprintf("%s new in %s: %s (%s) → %s", color(cGreen, "✦"), bold+displayFolder(folder)+reset, fresh[0], size(total), link)
	}
	return fmt.Sprintf("%s %d new in %s (%s): %s → %s", color(cGreen, "✦"), len(fresh), bold+displayFolder(folder)+reset,
		size(total), names(fresh, 3), link)
}

// tally: "US×10 DE×4", largest first
func tally(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return m[keys[i]] > m[keys[j]] || m[keys[i]] == m[keys[j]] && keys[i] < keys[j] })
	parts := []string{}
	for i, k := range keys {
		if i == 4 {
			parts = append(parts, "…")
			break
		}
		if k == "" {
			k = "?"
		}
		parts = append(parts, fmt.Sprintf("%s×%d", k, m[k]))
	}
	return strings.Join(parts, " ")
}

func top(m map[string]int) (string, int) {
	best, n := "", 0
	for k, v := range m {
		if v > n || v == n && k < best {
			best, n = k, v
		}
	}
	return best, n
}

// fit: at most max lines; the rest becomes one "+N more" line
func fit(lines []string, max int, hint string) []string {
	if len(lines) <= max {
		return lines
	}
	keep := append([]string{}, lines[:max-1]...)
	return append(keep, color(cGrey, fmt.Sprintf("… +%d more lines%s", len(lines)-(max-1), hint)))
}

// truncateBytes keeps a line inside IRC's 512-byte limit (with room for the
// prefix the server adds), cutting on a rune boundary
func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// short: the first 6 characters of a session id (enough to tell sessions apart)
func short(sid string) string {
	sid = clean(sid)
	if len(sid) > 6 {
		return sid[:6]
	}
	return sid
}
