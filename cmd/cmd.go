package cmd

import (
	_ "github.com/sikalabs/single-user-oidc-issuer/cmd/generate_key"
	"github.com/sikalabs/single-user-oidc-issuer/cmd/root"
	_ "github.com/sikalabs/single-user-oidc-issuer/cmd/server"
	_ "github.com/sikalabs/single-user-oidc-issuer/cmd/version"
	"github.com/spf13/cobra"
)

func Execute() {
	cobra.CheckErr(root.Cmd.Execute())
}
