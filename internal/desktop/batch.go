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

// sdkClient is the part of one account's SDK client that resolution uses.
type sdkClient struct {
	resolve batchResolve
	vaults  func(context.Context) ([]sdk.VaultOverview, error)
}
type batchFactory func(context.Context, string) (sdkClient, error)

func newClient(ctx context.Context, account string) (sdkClient, error) {
	client, err := sdk.NewClient(ctx, sdk.WithDesktopAppIntegration(account), sdk.WithIntegrationInfo("cop", "0.1.0"))
	if err != nil {
		return sdkClient{}, err
	}
	return sdkClient{
		resolve: client.Secrets().ResolveAll,
		vaults:  func(ctx context.Context) ([]sdk.VaultOverview, error) { return client.Vaults().List(ctx) },
	}, nil
}

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
	client, err := create(ctx, keys[0].Account)
	if err != nil {
		return nil, &batchError{20}
	}
	result, err := client.resolve(ctx, refs)
	if err != nil {
		return nil, resolutionFailure(err)
	}
	values := make([]local.BatchValue, len(keys))
	for i, k := range keys {
		values[i] = batchValue(result, k.Ref)
	}
	retryByVaultID(ctx, client, refs, values)
	return values, nil
}

func batchValue(result sdk.ResolveAllResponse, ref string) local.BatchValue {
	response, ok := result.IndividualResponses[ref]
	switch {
	case !ok:
	case response.Error != nil:
		switch response.Error.Type {
		case sdk.ResolveReferenceErrorTypeVariantVaultNotFound:
			return local.BatchValue{Code: 40}
		case sdk.ResolveReferenceErrorTypeVariantItemNotFound:
			return local.BatchValue{Code: 41}
		case sdk.ResolveReferenceErrorTypeVariantFieldNotFound:
			return local.BatchValue{Code: 42}
		}
	case response.Content != nil && len(response.Content.Secret) <= local.MaxSecret && !strings.ContainsRune(response.Content.Secret, 0):
		return local.BatchValue{Value: []byte(response.Content.Secret)}
	}
	return local.BatchValue{Code: 1}
}

// retryByVaultID resolves refs whose vault name the SDK could not match, using
// the ID of the one vault with that name. The SDK does not match built-in
// vaults such as Private or Employee by name, though op does. Values stay
// under the ref the user allowed; only the SDK sees the ID form.
func retryByVaultID(ctx context.Context, client sdkClient, refs []string, values []local.BatchValue) {
	retry := map[int]string{}
	for i, v := range values {
		if v.Code == 40 {
			retry[i] = ""
		}
	}
	if len(retry) == 0 || client.vaults == nil {
		return
	}
	vaults, err := client.vaults(ctx)
	if err != nil {
		return
	}
	var byID []string
	for i := range retry {
		name, rest, _ := strings.Cut(strings.TrimPrefix(refs[i], "op://"), "/")
		id, several := matchVault(name, vaults)
		if several {
			values[i].Code = 43
		}
		if id == "" {
			delete(retry, i)
			continue
		}
		retry[i] = "op://" + id + "/" + rest
		byID = append(byID, retry[i])
	}
	if len(byID) == 0 {
		return
	}
	result, err := client.resolve(ctx, byID)
	if err != nil {
		return
	}
	for i, ref := range retry {
		values[i] = batchValue(result, ref)
	}
}

// matchVault returns the ID of the one vault the name selects. It tries the
// exact title, then the title in any case, then the built-in personal vault.
func matchVault(name string, vaults []sdk.VaultOverview) (id string, several bool) {
	personal := strings.EqualFold(name, "Private") || strings.EqualFold(name, "Personal") || strings.EqualFold(name, "Employee")
	for _, match := range []func(sdk.VaultOverview) bool{
		func(v sdk.VaultOverview) bool { return v.Title == name },
		func(v sdk.VaultOverview) bool { return strings.EqualFold(v.Title, name) },
		func(v sdk.VaultOverview) bool { return personal && v.VaultType == sdk.VaultTypePersonal },
	} {
		var found []string
		for _, v := range vaults {
			if match(v) {
				found = append(found, v.ID)
			}
		}
		if len(found) == 1 {
			return found[0], false
		}
		if len(found) > 1 {
			return "", true
		}
	}
	return "", false
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
	values, err := resolveBatch(context.Background(), keys, newClient)
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
	var client sdkClient
	factory := func(ctx context.Context, selected string) (sdkClient, error) {
		if account != "" && account != selected {
			return sdkClient{}, errors.New("account changed")
		}
		account = selected
		if client.resolve != nil {
			return client, nil
		}
		created, err := newClient(ctx, account)
		if err != nil {
			return sdkClient{}, err
		}
		client = created
		return client, nil
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
