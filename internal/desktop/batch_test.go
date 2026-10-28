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
	factory := func(_ context.Context, account string) (batchResolve, error) {
		clients++
		if account != "account" {
			t.Fatal("wrong account")
		}
		return func(_ context.Context, refs []string) (sdk.ResolveAllResponse, error) {
			calls++
			if len(refs) != 2 {
				t.Fatal("not batched")
			}
			missing := sdk.NewResolveReferenceErrorTypeVariantFieldNotFound()
			return sdk.ResolveAllResponse{IndividualResponses: map[string]sdk.Response[sdk.ResolvedReference, sdk.ResolveReferenceError]{refs[0]: {Content: &sdk.ResolvedReference{Secret: "synthetic"}}, refs[1]: {Error: &missing}}}, nil
		}, nil
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
	_, err := resolveBatch(context.Background(), []local.Key{{Project: "example", Account: "account", Ref: "op://vault/item/key"}}, func(context.Context, string) (batchResolve, error) {
		calls++
		return nil, errors.New("synthetic-sensitive-detail")
	})
	if err == nil || calls != 1 || err.Error() == "synthetic-sensitive-detail" {
		t.Fatal("unsafe authentication failure")
	}
}

func TestBatchResolutionFailureIsNotInitializationFailure(t *testing.T) {
	keys := []local.Key{{Project: "example", Account: "account", Ref: "op://vault/item/key"}}
	_, err := resolveBatch(context.Background(), keys, func(context.Context, string) (batchResolve, error) {
		return func(context.Context, []string) (sdk.ResolveAllResponse, error) {
			return sdk.ResolveAllResponse{}, errors.New("sensitive diagnostic")
		}, nil
	})
	var failure *batchError
	if !errors.As(err, &failure) || failure.code != 21 {
		t.Fatal("incorrect failure stage")
	}
}
