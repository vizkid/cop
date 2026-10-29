//go:build cgo

package desktop

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	sdk "github.com/1password/onepassword-sdk-go"
	"github.com/vizkid/cop/internal/local"
)

type batchError struct{ code int }

func (e *batchError) Error() string { return "SDK batch failed" }

func resolutionFailure(err error) error {
	text := strings.ToLower(err.Error())
	code := 21
	switch {
	case strings.Contains(text, "session") && strings.Contains(text, "expired"):
		code = 23
	case strings.Contains(text, "denied") || strings.Contains(text, "not authorized") || strings.Contains(text, "permission"):
		code = 24
	case strings.Contains(text, "cancel"):
		code = 22
	}
	return &batchError{code}
}

type batchResolve func(context.Context, []string) (sdk.ResolveAllResponse, error)
type batchFactory func(context.Context, string) (batchResolve, error)

func resolveBatch(ctx context.Context, keys []local.Key, create batchFactory) ([]local.BatchValue, error) {
	if len(keys) == 0 || len(keys) > local.MaxEntries {
		return nil, errors.New("invalid batch")
	}
	refs := make([]string, len(keys))
	for i, k := range keys {
		if k.Validate() != nil || k.Project != keys[0].Project || k.Account != keys[0].Account {
			return nil, errors.New("mixed batch authority")
		}
		refs[i] = k.Ref
	}
	resolve, err := create(ctx, keys[0].Account)
	if err != nil {
		return nil, &batchError{20}
	}
	result, err := resolve(ctx, refs)
	if err != nil {
		return nil, resolutionFailure(err)
	}
	values := make([]local.BatchValue, len(keys))
	for i, k := range keys {
		response, ok := result.IndividualResponses[k.Ref]
		values[i].Code = 1
		if !ok {
			continue
		}
		if response.Error != nil {
			switch response.Error.Type {
			case sdk.ResolveReferenceErrorTypeVariantVaultNotFound:
				values[i].Code = 40
			case sdk.ResolveReferenceErrorTypeVariantItemNotFound:
				values[i].Code = 41
			case sdk.ResolveReferenceErrorTypeVariantFieldNotFound:
				values[i].Code = 42
			}
		} else if response.Content != nil && len(response.Content.Secret) <= local.MaxSecret && !strings.ContainsRune(response.Content.Secret, 0) {
			values[i] = local.BatchValue{Value: []byte(response.Content.Secret)}
		}
	}
	return values, nil
}

func RunBatch() {
	if local.DisableCoreDumps() != nil {
		os.Exit(1)
	}
	var keys []local.Key
	d := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20))
	d.DisallowUnknownFields()
	if d.Decode(&keys) != nil || d.Decode(new(any)) != io.EOF {
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
	values, err := resolveBatch(context.Background(), keys, func(ctx context.Context, account string) (batchResolve, error) {
		client, err := sdk.NewClient(ctx, sdk.WithDesktopAppIntegration(account), sdk.WithIntegrationInfo("cop", "0.1.0"))
		if err != nil {
			return nil, err
		}
		return client.Secrets().ResolveAll, nil
	})
	if err != nil {
		var failure *batchError
		if errors.As(err, &failure) {
			os.Exit(failure.code)
		}
		os.Exit(1)
	}
	defer func() {
		for _, v := range values {
			clear(v.Value)
		}
	}()
	if json.NewEncoder(output).Encode(values) != nil {
		os.Exit(1)
	}
}

// RunSession keeps one account's SDK client while the parent submits project batches.
func RunSession() {
	if local.DisableCoreDumps() != nil {
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
	var account string
	var resolve batchResolve
	factory := func(ctx context.Context, selected string) (batchResolve, error) {
		if account != "" && account != selected {
			return nil, errors.New("account changed")
		}
		account = selected
		if resolve != nil {
			return resolve, nil
		}
		client, err := sdk.NewClient(ctx, sdk.WithDesktopAppIntegration(account), sdk.WithIntegrationInfo("cop", "0.1.0"))
		if err != nil {
			return nil, err
		}
		resolve = client.Secrets().ResolveAll
		return resolve, nil
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 8192), 1<<20)
	for scanner.Scan() {
		var keys []local.Key
		if json.Unmarshal(scanner.Bytes(), &keys) != nil {
			os.Exit(1)
		}
		values, err := resolveBatch(context.Background(), keys, factory)
		if err != nil {
			code := 1
			var failure *batchError
			if errors.As(err, &failure) {
				code = failure.code
			}
			values = make([]local.BatchValue, len(keys))
			for i := range values {
				values[i].Code = code
			}
		}
		err = json.NewEncoder(output).Encode(values)
		for _, v := range values {
			clear(v.Value)
		}
		if err != nil {
			os.Exit(1)
		}
	}
}
