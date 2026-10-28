//go:build cgo

// Package desktop resolves fields in disposable daemon subprocesses.
package desktop

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"

	sdk "github.com/1password/onepassword-sdk-go"
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
	client, err := sdk.NewClient(context.Background(), sdk.WithDesktopAppIntegration(key.Account), sdk.WithIntegrationInfo("cop", "0.1.0"))
	if err != nil {
		os.Exit(20)
	}
	value, err := client.Secrets().Resolve(context.Background(), key.Ref)
	if err != nil {
		if strings.Contains(err.Error(), "no vault matched the secret reference query") {
			os.Exit(40)
		}
		if strings.Contains(err.Error(), "no item matched the secret reference query") {
			os.Exit(41)
		}
		if strings.Contains(err.Error(), "specified field cannot be found") {
			os.Exit(42)
		}
		os.Exit(1)
	}
	if len(value) > local.MaxSecret || strings.IndexByte(value, 0) >= 0 {
		os.Exit(1)
	}
	if _, err := io.WriteString(output, value); err != nil {
		os.Exit(1)
	}
}
