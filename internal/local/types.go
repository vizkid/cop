package local

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// Fixed limits. The README documents them under Settings.
const (
	MaxSecret = 64 << 10 // bytes in one value
	// MaxEntries caps cached fields per daemon, keys per SDK batch, and entries per replica snapshot.
	MaxEntries = 128
	// MaxQueue caps ordinary loads, separately for loads in flight and loads waiting.
	MaxQueue = 64
	// maxHistory caps the load records that status shows.
	maxHistory = 128
)

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func ValidProjectName(name string) bool { return namePattern.MatchString(name) }

type Key struct {
	Project   string `json:"project"`
	Account   string `json:"account"`
	Ref       string `json:"ref"`
	Use       string `json:"use,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
}

type Request struct {
	Action string `json:"action"`
	Peer   string `json:"peer,omitempty"`
	Topcop string `json:"topcop,omitempty"`
	Data   []byte `json:"data,omitempty"`
	Key
}

type Result struct {
	Error     string  `json:"error,omitempty"`
	Status    string  `json:"status,omitempty"`
	Value     []byte  `json:"value,omitempty"`
	Signature []byte  `json:"signature,omitempty"`
	View      *Status `json:"view,omitempty"`
}

type JobStatus struct {
	ID uint64 `json:"id"`
	Key
	State   string    `json:"state"`
	Reason  string    `json:"reason,omitempty"`
	Created time.Time `json:"created"`
}

type Cached struct {
	Key
	Expires time.Time `json:"expires"`
}

type Status struct {
	Network  *NetworkStatus   `json:"network,omitempty"`
	Projects map[string][]Key `json:"projects"`
	Requests []JobStatus      `json:"requests"`
	Cache    []Cached         `json:"cache"`
}

func validText(s string) bool {
	return s != "" && len(s) <= 2048 && !strings.ContainsFunc(s, unicode.IsControl)
}

func (k Key) Validate() error {
	if k.Use != "" && k.Use != "ssh-sign" {
		return errors.New("unsupported key use")
	}
	if k.Use == "ssh-sign" {
		if _, err := signingPublic(k.PublicKey); err != nil {
			return err
		}
	} else if k.PublicKey != "" {
		return errors.New("public identity requires signing use")
	}
	if !ValidProjectName(k.Project) || !validText(k.Account) || !validText(k.Ref) || !strings.HasPrefix(k.Ref, "op://") {
		return errors.New("invalid project, account, or reference")
	}
	// Preserve the exact spelling; never expand aliases or discover other fields.
	parts := strings.Split(strings.TrimPrefix(k.Ref, "op://"), "/")
	if len(parts) < 3 || len(parts) > 4 || strings.ContainsAny(k.Ref, "?#") {
		return errors.New("reference must name an exact field without query parameters")
	}
	for _, part := range parts {
		decoded, err := url.PathUnescape(part)
		if err != nil || !validText(decoded) || decoded == "*" {
			return errors.New("invalid reference component")
		}
	}
	field, _ := url.PathUnescape(parts[len(parts)-1])
	if k.Use != "ssh-sign" && strings.EqualFold(strings.ReplaceAll(field, "_", " "), "private key") {
		return errors.New("private-key delivery is unsupported; signing is deferred")
	}
	return nil
}
