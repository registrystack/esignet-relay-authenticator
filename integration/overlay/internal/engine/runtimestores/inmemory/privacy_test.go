package inmemory

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

func TestRuntimeKeysStayOutOfDebugLogs(t *testing.T) {
	if os.Getenv("ESIGNET_RUNTIME_LOG_TEST_CHILD") == "1" {
		store := newInMemoryStore("test")
		ctx := context.Background()
		if err := store.Put(ctx, providers.NamespaceAuthzCode, "private-authorization-code", []byte("private-stored-value"), 60); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PutIfNotExists(ctx, providers.NamespaceAuthzCode, "private-authorization-code-other", []byte("private-stored-value"), 60); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Take(ctx, providers.NamespaceAuthzCode, "private-authorization-code"); err != nil {
			t.Fatal(err)
		}
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestRuntimeKeysStayOutOfDebugLogs$")
	command.Env = append(os.Environ(), "ESIGNET_RUNTIME_LOG_TEST_CHILD=1", "LOG_LEVEL=debug")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("child debug-log regression failed: %v", err)
	}
	if strings.Contains(string(output), "private-authorization-code") || strings.Contains(string(output), "private-stored-value") {
		t.Fatal("runtime key or value entered debug log")
	}
	if strings.Count(string(output), `"namespace"`) != 3 {
		t.Fatal("expected all three debug operations to retain namespace diagnostics")
	}
}
