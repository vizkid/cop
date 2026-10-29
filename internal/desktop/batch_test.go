//go:build cgo

package desktop

import (
	"context"
	"errors"
	sdk "github.com/1password/onepassword-sdk-go"
	"github.com/vizkid/cop/internal/local"
	"testing"
)

func TestBatchUsesOneClientAndOneResolveAll(t *testing.T) {
	keys := []local.Key{{Project: "example", Account: "account", Ref: "op://vault/item/one"}, {Project: "example", Account: "account", Ref: "op://vault/item/two"}}
	clients, calls := 0, 0
	factory := func(_ context.Context, account string) (sdkClient, error) {
		clients++
		if account != "account" {
			t.Fatal("wrong account")
		}
		return sdkClient{resolve: func(_ context.Context, refs []string) (sdk.ResolveAllResponse, error) {
			calls++
			if len(refs) != 2 {
				t.Fatal("not batched")
			}
			missing := sdk.NewResolveReferenceErrorTypeVariantFieldNotFound()
			return sdk.ResolveAllResponse{IndividualResponses: map[string]sdk.Response[sdk.ResolvedReference, sdk.ResolveReferenceError]{refs[0]: {Content: &sdk.ResolvedReference{Secret: "synthetic"}}, refs[1]: {Error: &missing}}}, nil
		}}, nil
	}
	values, err := resolveBatch(context.Background(), keys, factory)
	if err != nil || clients != 1 || calls != 1 || string(values[0].Value) != "synthetic" || values[1].Code != 42 {
		t.Fatal("batch result incorrect")
	}
	keys[1].Account = "other"
	if _, err := resolveBatch(context.Background(), keys, factory); err == nil || clients != 1 {
		t.Fatal("cross-account batch authenticated")
	}
	keys[1].Account = "account"
	keys[1].Project = "other"
	if _, err := resolveBatch(context.Background(), keys, factory); err == nil || clients != 1 {
		t.Fatal("cross-project batch authenticated")
	}
}
func TestBatchAuthenticationFailureDoesNotRetry(t *testing.T) {
	calls := 0
	_, err := resolveBatch(context.Background(), []local.Key{{Project: "example", Account: "account", Ref: "op://vault/item/key"}}, func(context.Context, string) (sdkClient, error) {
		calls++
		return sdkClient{}, errors.New("synthetic-sensitive-detail")
	})
	if err == nil || calls != 1 || err.Error() == "synthetic-sensitive-detail" {
		t.Fatal("unsafe authentication failure")
	}
}

func TestBatchResolutionFailureIsNotInitializationFailure(t *testing.T) {
	keys := []local.Key{{Project: "example", Account: "account", Ref: "op://vault/item/key"}}
	_, err := resolveBatch(context.Background(), keys, func(context.Context, string) (sdkClient, error) {
		return sdkClient{resolve: func(context.Context, []string) (sdk.ResolveAllResponse, error) {
			return sdk.ResolveAllResponse{}, errors.New("sensitive diagnostic")
		}}, nil
	})
	var failure *batchError
	if !errors.As(err, &failure) || failure.code != 21 {
		t.Fatal("incorrect failure stage")
	}
}

// fakeVaults is an SDK that matches vaults only by ID, like the desktop SDK
// does for built-in vaults.
type fakeVaults struct {
	vaults   []sdk.VaultOverview
	listErr  error
	secrets  map[string]string
	resolves [][]string
	lists    int
}

func (f *fakeVaults) client(context.Context, string) (sdkClient, error) {
	return sdkClient{
		resolve: func(_ context.Context, refs []string) (sdk.ResolveAllResponse, error) {
			f.resolves = append(f.resolves, refs)
			out := map[string]sdk.Response[sdk.ResolvedReference, sdk.ResolveReferenceError]{}
			for _, ref := range refs {
				if secret, ok := f.secrets[ref]; ok {
					out[ref] = sdk.Response[sdk.ResolvedReference, sdk.ResolveReferenceError]{Content: &sdk.ResolvedReference{Secret: secret}}
				} else {
					missing := sdk.NewResolveReferenceErrorTypeVariantVaultNotFound()
					out[ref] = sdk.Response[sdk.ResolvedReference, sdk.ResolveReferenceError]{Error: &missing}
				}
			}
			return sdk.ResolveAllResponse{IndividualResponses: out}, nil
		},
		vaults: func(context.Context) ([]sdk.VaultOverview, error) {
			f.lists++
			return f.vaults, f.listErr
		},
	}, nil
}

func vaultKeys(refs ...string) []local.Key {
	keys := make([]local.Key, len(refs))
	for i, ref := range refs {
		keys[i] = local.Key{Project: "example", Account: "account", Ref: ref}
	}
	return keys
}

func TestVaultNameResolvesThroughSingleMatchingID(t *testing.T) {
	f := &fakeVaults{
		vaults:  []sdk.VaultOverview{{ID: "sharedid", Title: "Shared", VaultType: sdk.VaultTypeUserCreated}, {ID: "teamid", Title: "Team Vault", VaultType: sdk.VaultTypeUserCreated}},
		secrets: map[string]string{"op://Shared/item/ok": "first", "op://teamid/item/field": "second", "op://teamid/other/field": "third"},
	}
	values, err := resolveBatch(context.Background(), vaultKeys("op://Shared/item/ok", "op://Team Vault/item/field", "op://team vault/other/field"), f.client)
	if err != nil || string(values[0].Value) != "first" || string(values[1].Value) != "second" || string(values[2].Value) != "third" {
		t.Fatalf("values %+v, err %v", values, err)
	}
	if f.lists != 1 || len(f.resolves) != 2 || len(f.resolves[1]) != 2 {
		t.Fatalf("want one vault list and one retry of two refs, got %d lists and resolves %v", f.lists, f.resolves)
	}
}

func TestBuiltInVaultNamesResolveToPersonalVault(t *testing.T) {
	for _, name := range []string{"Private", "Employee", "personal"} {
		f := &fakeVaults{
			vaults:  []sdk.VaultOverview{{ID: "sharedid", Title: "Shared", VaultType: sdk.VaultTypeEveryone}, {ID: "mineid", Title: "", VaultType: sdk.VaultTypePersonal}},
			secrets: map[string]string{"op://mineid/LinuxRex/credential": "synthetic"},
		}
		values, err := resolveBatch(context.Background(), vaultKeys("op://"+name+"/LinuxRex/credential"), f.client)
		if err != nil || string(values[0].Value) != "synthetic" {
			t.Fatalf("%s: values %+v, err %v", name, values, err)
		}
	}
}

func TestVaultNameWithSeveralMatchesIsAmbiguous(t *testing.T) {
	f := &fakeVaults{vaults: []sdk.VaultOverview{{ID: "a", Title: "Dup"}, {ID: "b", Title: "Dup"}}, secrets: map[string]string{"op://a/item/field": "wrong"}}
	values, err := resolveBatch(context.Background(), vaultKeys("op://Dup/item/field"), f.client)
	if err != nil || values[0].Code != 43 || values[0].Value != nil || len(f.resolves) != 1 {
		t.Fatalf("values %+v, err %v, resolves %v", values, err, f.resolves)
	}
}

func TestUnknownVaultNameKeepsVaultNotFound(t *testing.T) {
	for _, f := range []*fakeVaults{
		{vaults: []sdk.VaultOverview{{ID: "a", Title: "Other"}}},
		{listErr: errors.New("synthetic list failure")},
	} {
		values, err := resolveBatch(context.Background(), vaultKeys("op://Missing/item/field"), f.client)
		if err != nil || values[0].Code != 40 || len(f.resolves) != 1 {
			t.Fatalf("values %+v, err %v, resolves %v", values, err, f.resolves)
		}
	}
}

func TestResolvedRefsDoNotListVaults(t *testing.T) {
	f := &fakeVaults{secrets: map[string]string{"op://Shared/item/field": "synthetic"}}
	if _, err := resolveBatch(context.Background(), vaultKeys("op://Shared/item/field"), f.client); err != nil || f.lists != 0 {
		t.Fatalf("err %v, lists %d", err, f.lists)
	}
}
