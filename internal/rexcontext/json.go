package rexcontext

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Ignore new schema fields, but reject duplicate keys and trailing documents.
func decode(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	if err := unique(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return json.Unmarshal(data, target)
}

func unique(d *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds limit")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			name = strings.ToLower(name)
			if !ok || seen[name] {
				return errors.New("duplicate JSON key")
			}
			seen[name] = true
		}
		if err := unique(d, depth+1); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}
