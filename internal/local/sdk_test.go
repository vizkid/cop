package local

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSDKPipeFailures(t *testing.T) {
	for _, body := range []string{
		"printf 'bad\\000value' >&3",
		"head -c 65537 /dev/zero >&3",
		"printf synthetic-secret >&3; printf synthetic-secret >&2; exit 1",
		"exec sleep 20",
	} {
		t.Run(body, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "worker")
			if err := os.WriteFile(file, []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			resolve, err := SDK(file)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			value, err := resolve(ctx, testKey)
			if err == nil || len(value) != 0 || strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatal("unsafe worker result")
			}
		})
	}
}
