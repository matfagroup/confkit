package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/matfagroup/confkit"
)

// Synthetic secrets for probe — names are arbitrary and not service-specific.
type probeSecrets struct {
	Alpha struct {
		User string `vault:"shared/alpha:user"`
		Pass string `vault:"shared/alpha:pass"`
	}
	Beta struct {
		Token string `vault:"self/beta:token"`
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	opts, err := confkit.OptionsFromEnv()
	if err != nil {
		return err
	}

	ctx := context.Background()
	loader, err := confkit.New(ctx, opts)
	if err != nil {
		return err
	}
	defer loader.Close()

	fmt.Printf("env:      %s\n", loader.Env())
	fmt.Printf("service:  %s\n", loader.Service())
	fmt.Printf("local:    %v\n", loader.IsLocal())

	info, err := loader.TokenInfo(ctx)
	if err != nil {
		return fmt.Errorf("token info: %w", err)
	}
	if info != nil {
		fmt.Printf("accessor: %s\n", info.Accessor)
		fmt.Printf("ttl:      %s\n", info.TTL)
		fmt.Printf("renewable:%v\n", info.Renewable)
		fmt.Printf("policies: %s\n", strings.Join(info.Policies, ", "))
	} else {
		fmt.Println("token:    (none — local mode)")
	}

	var secrets probeSecrets
	if err := loader.Into(ctx, &secrets); err != nil {
		return fmt.Errorf("into: %w", err)
	}
	printMasked("Alpha.User", secrets.Alpha.User)
	printMasked("Alpha.Pass", secrets.Alpha.Pass)
	printMasked("Beta.Token", secrets.Beta.Token)
	fmt.Printf("reads:    %d\n", loader.SecretReads())

	if err := loader.RevokeSelf(ctx); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	fmt.Println("revoked:  ok")
	return nil
}

func printMasked(name, value string) {
	fmt.Printf("%s: %s (%d chars)\n", name, strings.Repeat("*", 4), len(value))
}
