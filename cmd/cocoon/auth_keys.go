package main

import (
	"context"
	"fmt"
	"time"

	"github.com/urfave/cli/v2"
)

var runAuthKeys = &cli.Command{
	Name:     "auth-keys",
	Usage:    "lists or revokes an account's sign-in keys",
	Category: "account",
	Description: "Accounts created with an authKey sign in through the OAuth jwt-bearer grant with that key. " +
		"Revoking a key stops it signing in and revokes the OAuth sessions issued through it.\n\n" +
		"Uses the same config as `run` (COCOON_* env vars). Run with the PDS stopped " +
		"(it opens the same database).",
	Subcommands: []*cli.Command{
		{
			Name:  "list",
			Usage: "lists an account's sign-in keys",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "did",
					Required: true,
					Usage:    "the account's did",
				},
			},
			Action: func(cmd *cli.Context) error {
				did := cmd.String("did")

				s, err := newAgentServer(cmd)
				if err != nil {
					return err
				}
				if err := s.Migrate(); err != nil {
					return fmt.Errorf("error migrating database: %w", err)
				}

				keys, err := s.ListAuthKeys(context.Background(), did)
				if err != nil {
					return fmt.Errorf("error listing sign-in keys: %w", err)
				}
				if len(keys) == 0 {
					fmt.Printf("No sign-in keys for %s.\n", did)
					return nil
				}
				for _, k := range keys {
					status := "active"
					if k.RevokedAt != nil {
						status = "revoked " + k.RevokedAt.Format(time.RFC3339)
					}
					fmt.Printf("%s  added %s  %s\n", k.DidKey, k.CreatedAt.Format(time.RFC3339), status)
				}
				return nil
			},
		},
		{
			Name:  "revoke",
			Usage: "revokes one of an account's sign-in keys (or all of them)",
			Description: "Revoking stops the key signing in through the jwt-bearer grant and revokes the OAuth " +
				"sessions issued through it.",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "did",
					Required: true,
					Usage:    "the account's did",
				},
				&cli.StringFlag{
					Name:    "key",
					Aliases: []string{"did-key"},
					Usage:   "the did:key to revoke; omit to revoke all of the account's sign-in keys",
				},
			},
			Action: func(cmd *cli.Context) error {
				did := cmd.String("did")
				didKey := cmd.String("key")

				s, err := newAgentServer(cmd)
				if err != nil {
					return err
				}
				if err := s.Migrate(); err != nil {
					return fmt.Errorf("error migrating database: %w", err)
				}

				revoked, err := s.RevokeAuthKey(context.Background(), did, didKey)
				if err != nil {
					return fmt.Errorf("error revoking sign-in key: %w", err)
				}
				if !revoked {
					fmt.Println("No active sign-in keys matched; nothing was revoked.")
					return nil
				}
				fmt.Println("Sign-in key(s) revoked. Sessions signed in with them were signed out.")
				return nil
			},
		},
	},
}
