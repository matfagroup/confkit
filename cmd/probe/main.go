package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/matfagroup/confkit"
)

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

	if err := loader.RevokeSelf(ctx); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	fmt.Println("revoked:  ok")
	return nil
}
