//go:build cgo

// Package desktop resolves fields in disposable daemon subprocesses.
package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/vizkid/cop/internal/local"
)

func Run() {
	if local.DisableCoreDumps() != nil {
		os.Exit(1)
	}
	var key local.Key
	if json.NewDecoder(io.LimitReader(os.Stdin, 8192)).Decode(&key) != nil || key.Validate() != nil {
		os.Exit(1)
	}
	output := os.NewFile(3, "cop-secret-pipe")
	if output == nil {
		os.Exit(1)
	}
	defer output.Close()
	info, err := output.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		os.Exit(1)
	}
	values, err := resolveBatch(context.Background(), []local.Key{key}, newClient)
	if err != nil {
		var failure *batchError
		if errors.As(err, &failure) {
			os.Exit(failure.code)
		}
		os.Exit(1)
	}
	if values[0].Code != 0 {
		os.Exit(values[0].Code)
	}
	value := values[0].Value
	defer clear(value)
	if _, err := output.Write(value); err != nil {
		os.Exit(1)
	}
}
