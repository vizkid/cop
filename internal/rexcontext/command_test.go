package rexcontext

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRexSubprocessBoundsAndRedaction(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
case "$1" in
  fail) printf private-diagnostic; printf private-diagnostic >&2; exit 1 ;;
  large) head -c 2097153 /dev/zero ;;
  delay) sleep 10 ;;
  *) printf '{"mode":"test"}' ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "rex"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, mode := range []string{"fail", "large", "delay"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			if mode == "delay" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
			}
			defer cancel()
			data, err := runRex(ctx, mode)
			if err == nil || len(data) != 0 || strings.Contains(err.Error(), "private-diagnostic") {
				t.Fatal("subprocess limit or redaction failed")
			}
		})
	}
}
