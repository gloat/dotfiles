// voidbot: posts the void-media Worker's events (operator key entries, links,
// uploads, the pause switch, library changes) to a private IRC channel on the
// local Ergo server, new library files to an optional public channel, and
// takes !status / !pause / !resume / !pending from the owner's Ergo account.
//
// It polls the Worker's admin route (the Ledger's event queue), so nothing on
// the VPS listens for the Worker, and events wait in the queue while the bot
// is down. The cursor is saved after every post, so a restart never repeats one.
//
//	voidbot -config /etc/voidbot/config.json
//	voidbot -config config.json -dry-run   (print the last events as lines, no IRC)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ergochat/irc-go/ircevent"
	"github.com/ergochat/irc-go/ircmsg"
)

// State is kept in the state file between runs.
type State struct {
	Cursor    int64   `json:"cursor"`     // the last event id posted
	WarnLevel float64 `json:"warn_level"` // the highest budget_warn step already announced
}

func loadState(path string) (*State, bool) {
	var s State
	raw, err := os.ReadFile(path)
	if err != nil {
		return &s, false
	}
	if json.Unmarshal(raw, &s) != nil {
		return &State{}, false
	}
	return &s, true
}

// save writes a temp file and renames it, so a crash never leaves half a file
func (s *State) save(path string) error {
	raw, _ := json.Marshal(s)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type Bot struct {
	cfg    *Config
	irc    *ircevent.Connection
	worker *Worker
	state  *State
	joined atomic.Bool // in the ops channel: only then are events taken off the queue
	retry  atomic.Bool // a rejoin of the ops channel is scheduled
	wake   chan struct{}
	mu     sync.Mutex // one poll at a time
	sys    sysShared  // storage + IRC users for the public sysinfo file (sysinfo.go)
}

const maxLine = 420 // bytes per PRIVMSG text, well inside IRC's 512 with the prefix

func main() {
	cfgPath := flag.String("config", "/etc/voidbot/config.json", "config file")
	dry := flag.Int("dry-run", 0, "print the last N events as IRC lines and exit (no IRC, cursor untouched)")
	flag.Parse()
	log.SetFlags(0) // runit's logger adds the time

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	worker := newWorker(cfg)
	if *dry > 0 {
		dryRun(cfg, worker, *dry)
		return
	}

	state, ok := loadState(cfg.StateFile)
	if !ok {
		// first start: begin at the newest event instead of replaying the queue.
		// Retried (not fatal), so a Worker that's down or not deployed yet
		// doesn't make runit restart the bot every second
		id, err := worker.newestID()
		for err != nil {
			log.Printf("first start, reading the queue: %v (retrying in 60 s)", err)
			time.Sleep(60 * time.Second)
			id, err = worker.newestID()
		}
		state.Cursor = id
		if err := state.save(cfg.StateFile); err != nil {
			log.Fatalf("state: %v", err)
		}
		log.Printf("first start: watching events after #%d", id)
	}

	b := &Bot{cfg: cfg, worker: worker, state: state, wake: make(chan struct{}, 1)}
	b.irc = &ircevent.Connection{
		Server:          cfg.Server,
		UseTLS:          cfg.TLS,
		Nick:            cfg.Nick,
		User:            "voidbot",
		RealName:        "void-media events",
		SASLLogin:       cfg.SASLLogin,
		SASLPassword:    cfg.SASLPassword,
		RequestCaps:     []string{"account-tag", "message-tags", "server-time", "batch"},
		QuitMessage:     "brb",
		ReconnectFreq:   15 * time.Second,
		AllowTruncation: true,
		Log:             log.Default(),
	}
	b.irc.AddConnectCallback(b.onConnect)
	b.irc.AddDisconnectCallback(func(ircmsg.Message) { b.joined.Store(false) })
	b.irc.AddCallback("JOIN", b.onJoin)
	b.irc.AddCallback("PART", b.onLeave)
	b.irc.AddCallback("KICK", b.onLeave)
	b.irc.AddCallback("PRIVMSG", b.onPrivmsg)
	b.irc.AddCallback("266", b.onGlobalUsers) // LUSERS (sysinfo.go)
	for _, numeric := range []string{"403", "405", "471", "473", "474", "475", "477"} { // can't join: no such channel / too many / full / +i / banned / +k / +R
		b.irc.AddCallback(numeric, func(e ircmsg.Message) {
			log.Printf("can't join: %s", strings.Join(e.Params[1:], " "))
			if len(e.Params) > 1 && strings.EqualFold(e.Params[1], b.cfg.OpsChannel) {
				b.rejoinLater()
			}
		})
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		b.irc.Quit()
		time.Sleep(time.Second)
		os.Exit(0)
	}()

	go b.pollLoop()
	go b.sysinfoLoop()

	// the first connect is retried here (Ergo may still be starting); after
	// that, Loop() reconnects by itself. The wait doubles up to 5 minutes:
	// Ergo's login-throttling allows 3 failed SASL logins a minute, and a bot
	// hammering it with a wrong password would keep its own account locked
	wait := 15 * time.Second
	for {
		err := b.irc.Connect()
		if err == nil {
			break
		}
		log.Printf("connect %s: %v (retrying in %v)", cfg.Server, err, wait)
		time.Sleep(wait)
		wait = min(wait*2, 5*time.Minute)
	}
	b.irc.Loop()
}

func (b *Bot) onConnect(ircmsg.Message) {
	if mode := b.irc.ISupport()["BOT"]; mode != "" {
		b.irc.Send("MODE", b.irc.CurrentNick(), "+"+mode) // marks it as a bot in /whois
	}
	b.join(b.cfg.OpsChannel, b.cfg.OpsKey)
	if b.cfg.PublicChannel != "" {
		b.join(b.cfg.PublicChannel, "")
	}
}

func (b *Bot) join(channel, key string) {
	if key != "" {
		b.irc.Send("JOIN", channel, key)
	} else {
		b.irc.Join(channel)
	}
}

func (b *Bot) onJoin(e ircmsg.Message) {
	if len(e.Params) < 1 || e.Nick() != b.irc.CurrentNick() || !strings.EqualFold(e.Params[0], b.cfg.OpsChannel) {
		return
	}
	b.joined.Store(true)
	log.Printf("joined %s", b.cfg.OpsChannel)
	b.poke()
}

// parted or kicked from the ops channel: stop taking events, rejoin shortly
func (b *Bot) onLeave(e ircmsg.Message) {
	if len(e.Params) < 1 || !strings.EqualFold(e.Params[0], b.cfg.OpsChannel) {
		return
	}
	gone := e.Nick() == b.irc.CurrentNick()
	if e.Command == "KICK" {
		gone = len(e.Params) > 1 && e.Params[1] == b.irc.CurrentNick()
	}
	if gone {
		b.joined.Store(false)
		log.Printf("left %s", b.cfg.OpsChannel)
		b.rejoinLater()
	}
}

// rejoinLater tries the ops channel again in a minute (one timer at a time),
// so fixing the channel key or a ban needs no restart of the bot
func (b *Bot) rejoinLater() {
	if !b.retry.CompareAndSwap(false, true) {
		return
	}
	time.AfterFunc(time.Minute, func() {
		b.retry.Store(false)
		if !b.joined.Load() && b.irc.Connected() {
			b.join(b.cfg.OpsChannel, b.cfg.OpsKey)
		}
	})
}

func (b *Bot) poke() {
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

func (b *Bot) pollLoop() {
	t := time.NewTicker(b.cfg.poll())
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-b.wake:
		}
		for b.joined.Load() && b.poll() {
		}
	}
}

// poll posts one page of events; true = more are waiting
func (b *Bot) poll() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	page, err := b.worker.events(b.state.Cursor)
	if err != nil {
		log.Printf("events: %v", err)
		return false
	}
	b.sys.setR2(page)
	r := build(b.cfg, page.Events)
	warn, level := b.budgetWarning(page)
	if warn != "" {
		r.Ops = append(r.Ops, warn)
		r.Ping = true
	}
	ops := fit(r.Ops, b.cfg.MaxLines, " (optool events)")
	if r.Ping && b.cfg.OwnerNick != "" && len(ops) > 0 {
		ops[0] = b.cfg.OwnerNick + ": " + ops[0]
	}
	// the cursor only moves once every line went out: a disconnect mid-way
	// means the page is posted again after the reconnect
	if !b.say(b.cfg.OpsChannel, ops) {
		return false
	}
	if b.cfg.PublicChannel != "" {
		b.say(b.cfg.PublicChannel, fit(r.Public, b.cfg.MaxLines, ""))
	}
	b.state.Cursor = page.Last
	b.state.WarnLevel = level
	if err := b.state.save(b.cfg.StateFile); err != nil {
		log.Printf("state: %v", err)
	}
	return page.More
}

func (b *Bot) say(target string, lines []string) bool {
	for _, l := range lines {
		if err := b.irc.Privmsg(target, truncateBytes(l, maxLine)); err != nil {
			log.Printf("send to %s: %v", target, err)
			return false
		}
	}
	return true
}

// budgetWarning: one line when storage crosses the next budget_warn step
// (80/90/95%); dropping back under a step re-arms it. level = the step now
// reached, saved once the line went out.
func (b *Bot) budgetWarning(p *EventPage) (string, float64) {
	if p.Budget <= 0 {
		return "", b.state.WarnLevel
	}
	frac := p.Used / p.Budget
	level := 0.0
	for _, w := range b.cfg.BudgetWarn {
		if frac >= w && w > level {
			level = w
		}
	}
	if level <= b.state.WarnLevel {
		return "", level
	}
	return fmt.Sprintf("%s storage at %s%.0f%%%s of the hard stop (%s of %s)", color(cRed, "💾"), bold, frac*100, reset,
		size(p.Used), size(p.Budget)), level
}

// ===== commands =====

func (b *Bot) onPrivmsg(e ircmsg.Message) {
	if len(e.Params) < 2 {
		return
	}
	text := strings.TrimSpace(e.Params[1])
	if !strings.HasPrefix(text, "!") {
		return
	}
	// only the owner's account (Ergo sets this tag; clients can't fake it),
	// and never old messages (history played back on join)
	if _, account := e.GetTag("account"); !b.cfg.isOwner(account) {
		return
	}
	if ok, ts := e.GetTag("time"); ok {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil && time.Since(t) > 2*time.Minute {
			return
		}
	}
	if e.HasTag("batch") {
		return
	}
	target := e.Params[0]
	if !strings.HasPrefix(target, "#") {
		target = e.Nick() // a private message: answer privately
	} else if !strings.EqualFold(target, b.cfg.OpsChannel) {
		return // never in the public channel: the answers show storage and channel names
	}
	fields := strings.Fields(text)
	by := "voidbot:" + e.Nick()
	go func() { // the Worker can take seconds: keep the IRC read loop free
		reply := b.command(strings.ToLower(fields[0]), by)
		if reply != "" {
			b.say(target, []string{reply})
		}
	}()
}

func (b *Bot) command(cmd, by string) string {
	switch cmd {
	case "!help":
		return "!status · !pause · !resume (uploads + links) · !pending (waiting for review)"
	case "!status", "!pause", "!resume":
		s, err := b.worker.status(strings.TrimPrefix(cmd, "!"), by)
		if err != nil {
			log.Printf("%s: %v", cmd, err)
			return color(cRed, "the Worker didn't answer: ") + clip(err.Error(), 200)
		}
		b.poke() // a pause/resume event is waiting: post it now
		return statusLine(s)
	case "!pending":
		p, err := b.worker.pending()
		if err != nil {
			log.Printf("%s: %v", cmd, err)
			return color(cRed, "the Worker didn't answer: ") + clip(err.Error(), 200)
		}
		if p.Files == 0 {
			return "nothing waiting for review"
		}
		files := []string{}
		for _, f := range p.Newest {
			files = append(files, fmt.Sprintf("%s (%s)", fileName(f.Key), size(f.Size)))
		}
		return fmt.Sprintf("%s waiting (%s), newest: %s", plural(p.Files, "file", "files"), size(p.Bytes), names(files, 4))
	}
	return ""
}

func statusLine(s *Status) string {
	state := color(cGreen, "open")
	if s.Paused {
		state = color(cOrange, bold+"PAUSED"+reset)
	}
	used := s.Stored + s.Reserved
	pct := 0.0
	if s.Budget > 0 {
		pct = used / s.Budget * 100
	}
	return fmt.Sprintf("uploads %s · storage %s of %s (%.1f%%) · %d in flight · channels: %s",
		state, size(used), size(s.Budget), pct, s.InFlight, strings.Join(s.Channels, " "))
}

// ===== -dry-run =====

func dryRun(cfg *Config, w *Worker, n int) {
	var p EventPage
	if err := w.call(map[string]any{"action": "events", "tail": n}, &p); err != nil {
		log.Fatal(err)
	}
	r := build(cfg, p.Events)
	show := func(ch string, lines []string) {
		for _, l := range fit(lines, cfg.MaxLines, " (optool events)") {
			fmt.Printf("%-8s %s\n", ch, stripCodes(truncateBytes(l, maxLine)))
		}
	}
	show(cfg.OpsChannel, r.Ops)
	if cfg.PublicChannel != "" {
		show(cfg.PublicChannel, r.Public)
	}
	fmt.Printf("(%d events, newest #%d; storage %s of %s)\n", len(p.Events), p.Last, size(p.Used), size(p.Budget))
}

// stripCodes removes IRC color/bold codes for terminal output
func stripCodes(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case 0x02, 0x0f, 0x1d, 0x1f:
		case 0x03:
			for j := 0; j < 2 && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9'; j++ {
				i++
			}
		default:
			out.WriteByte(s[i])
		}
	}
	return out.String()
}
