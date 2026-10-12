package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config is /etc/voidbot/config.json (root:_voidbot 640: it holds the SASL
// password and the Worker's admin token). See config.example.json.
type Config struct {
	Server       string `json:"server"`        // Ergo, e.g. 127.0.0.1:6667 (loopback: no TLS)
	TLS          bool   `json:"tls"`           // for a non-local server
	Nick         string `json:"nick"`          // also the SASL account unless sasl_login is set
	SASLLogin    string `json:"sasl_login"`    //
	SASLPassword string `json:"sasl_password"` //

	OpsChannel    string   `json:"ops_channel"`    // private: everything (IPs included)
	OpsKey        string   `json:"ops_key"`        // the channel key (+k), if any
	PublicChannel string   `json:"public_channel"` // optional: only files new in the library
	PublicSkip    []string `json:"public_skip"`    // key prefixes never announced publicly
	PublicURL     string   `json:"public_url"`     // listing base for the folder links

	Owners    []string `json:"owner_accounts"` // Ergo accounts whose !commands are obeyed
	OwnerNick string   `json:"owner_nick"`     // highlighted on important events (optional)

	AdminURL    string    `json:"admin_url"`   // the Worker's /_op/admin
	AdminToken  string    `json:"admin_token"` // = OP_ADMIN_TOKEN (optool keeps it in ~/.config/void-op/admin-token)
	PollSeconds int       `json:"poll_seconds"`
	MaxLines    int       `json:"max_lines"`   // per channel per poll, then "+N more"
	StateFile   string    `json:"state_file"`  // cursor + budget warning level
	BudgetWarn  []float64 `json:"budget_warn"` // storage fractions that ping the owner
	SysinfoFile string    `json:"sysinfo_file"` // the public server stats for the site's terminal ("" = off; sysinfo.go)
}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{
		Server:      "127.0.0.1:6667",
		Nick:        "voidbot",
		OpsChannel:  "#ops",
		PublicSkip:  []string{"public/"},
		PublicURL:   "https://media.gloat.ing/",
		AdminURL:    "https://media.gloat.ing/_op/admin",
		PollSeconds: 30,
		MaxLines:    8,
		StateFile:   "/var/lib/voidbot/state.json",
		BudgetWarn:  []float64{0.8, 0.9, 0.95},
		SysinfoFile: "/var/lib/voidbot-pub/sysinfo.json",
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields() // a typo in a field name is an error, not a silent default
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.SASLLogin == "" {
		c.SASLLogin = c.Nick
	}
	switch {
	case c.SASLPassword == "":
		return nil, errors.New("sasl_password is empty")
	case c.AdminToken == "":
		return nil, errors.New("admin_token is empty")
	case len(c.Owners) == 0:
		return nil, errors.New("owner_accounts is empty: nobody could use the commands")
	case !strings.HasPrefix(c.OpsChannel, "#"):
		return nil, errors.New("ops_channel must start with #")
	case c.PublicChannel != "" && !strings.HasPrefix(c.PublicChannel, "#"):
		return nil, errors.New("public_channel must start with #")
	}
	if c.PollSeconds < 10 {
		c.PollSeconds = 10
	}
	if c.MaxLines < 1 {
		c.MaxLines = 1
	}
	return c, nil
}

func (c *Config) poll() time.Duration { return time.Duration(c.PollSeconds) * time.Second }

func (c *Config) isOwner(account string) bool {
	for _, o := range c.Owners {
		if account != "" && strings.EqualFold(o, account) {
			return true
		}
	}
	return false
}
