package local

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSDKSessionHelper(t *testing.T) {
	if os.Getenv("COP_SESSION_HELPER") != "1" {
		return
	}
	output := os.NewFile(3, "pipe")
	defer output.Close()
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var keys []Key
		if json.Unmarshal(scanner.Bytes(), &keys) != nil {
			os.Exit(1)
		}
		if strings.HasSuffix(keys[0].Ref, "/slow") {
			time.Sleep(time.Minute)
		}
		values := make([]BatchValue, len(keys))
		for i := range values {
			values[i].Value = []byte(strconv.Itoa(os.Getpid()))
		}
		fmt.Fprintln(os.Stdout, "discarded synthetic worker output")
		if json.NewEncoder(output).Encode(values) != nil {
			os.Exit(1)
		}
	}
	os.Exit(0)
}
func TestSDKSessionReusesAccountProcessAndKillsOnTimeout(t *testing.T) {
	t.Setenv("COP_SESSION_HELPER", "1")
	resolve, closeSession, err := SDKSession(os.Args[0], "-test.run=^TestSDKSessionHelper$")
	if err != nil {
		t.Fatal(err)
	}
	defer closeSession()
	first, err := resolve(context.Background(), []Key{testKey})
	if err != nil {
		t.Fatal(err)
	}
	project := testKey
	project.Project = "beta"
	second, err := resolve(context.Background(), []Key{project})
	if err != nil {
		t.Fatal(err)
	}
	if string(first[0].Value) != string(second[0].Value) {
		t.Fatal("same account lost authenticated process")
	}
	account := testKey
	account.Account = "different"
	third, err := resolve(context.Background(), []Key{account})
	if err != nil {
		t.Fatal(err)
	}
	if string(first[0].Value) == string(third[0].Value) {
		t.Fatal("accounts shared native SDK state")
	}
	slow := testKey
	slow.Ref = "op://test/item/slow"
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := resolve(ctx, []Key{slow}); err == nil {
		t.Fatal("stuck native worker escaped timeout")
	}
	fourth, err := resolve(context.Background(), []Key{testKey})
	if err != nil {
		t.Fatal(err)
	}
	if string(fourth[0].Value) == string(first[0].Value) {
		t.Fatal("canceled session reused")
	}
	closeSession()
	if _, err := resolve(context.Background(), []Key{testKey}); err == nil {
		t.Fatal("closed session accepted work")
	}
}
