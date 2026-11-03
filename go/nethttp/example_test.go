// The example of docs/go.md, "Get started with net/http". It is compiled with
// the tests and never run, so the example cannot drift from the package. Keep
// the two the same: the body of Example_getStarted is the body of main.

package nethttp_test

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	keelie "github.com/apiable/keelie-sdk/go"
	"github.com/apiable/keelie-sdk/go/nethttp"
)

func env(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("%s is not set", name)
	}
	return value
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func Example_getStarted() {
	client, err := keelie.NewSDKCredential(keelie.SDKCredentialOptions{
		KeelieURL:    env("KEELIE_URL"),
		TokenURL:     env("KEELIE_TOKEN_URL"),
		ClientID:     env("KEELIE_SDK_CLIENT_ID"),
		ClientSecret: env("KEELIE_SDK_CLIENT_SECRET"),
	})
	check(err)
	verifier, err := keelie.NewTokenVerifier(env("KEELIE_ISSUER"), env("KEELIE_RESOURCE"), env("KEELIE_ORG_ID"), nil)
	check(err)
	metadata, err := keelie.NewProtectedResourceMetadata(env("KEELIE_RESOURCE"), env("KEELIE_ISSUER"), nil)
	check(err)
	scopes, err := keelie.NewScopeMap(map[string]string{"GET /v1/orders/{orderId}": "orders:read"})
	check(err)
	reporter, err := keelie.NewUsageReporter(client, nil)
	check(err)
	guard, err := nethttp.TokenGuard(verifier, metadata)
	check(err)
	scope := nethttp.ScopeGuard(scopes, metadata)

	mux := http.NewServeMux()
	mux.Handle("GET /v1/orders/{orderId}", scope(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := nethttp.ClaimsFrom(r)
		reporter.Record(keelie.Event{
			ClientID:      claims.AZP,
			CapabilityKey: "GET /v1/orders/{orderId}",
			Credits:       "1",
			ConsumerID:    claims.ConsumerID,
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"orderId": r.PathValue("orderId")})
	})))

	server := &http.Server{Addr: ":3000", Handler: guard(mux)}
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	stop, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	<-stop.Done()
	ctx, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	_ = server.Shutdown(ctx)
	reporter.Close(ctx)
}

// TestTheExampleIsTheOneInTheDocs fails when docs/go.md and Example_getStarted
// drift apart. Outside this repository, where the docs are not, it is skipped.
func TestTheExampleIsTheOneInTheDocs(t *testing.T) {
	docs, err := os.ReadFile("../../docs/go.md")
	if err != nil {
		t.Skip("docs/go.md is not here")
	}
	example, err := os.ReadFile("example_test.go")
	if err != nil {
		t.Fatal(err)
	}
	body := func(text, opening string) string {
		start := strings.Index(text, opening)
		if start < 0 {
			t.Fatalf("no %q", opening)
		}
		rest := text[start+len(opening):]
		return rest[:strings.Index(rest, "\n}\n")]
	}
	if body(string(docs), "func main() {") != body(string(example), "func Example_getStarted() {") {
		t.Fatal("docs/go.md and Example_getStarted differ: keep the two the same")
	}
}
