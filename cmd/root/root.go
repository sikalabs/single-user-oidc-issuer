package root

import (
	"github.com/sikalabs/single-user-oidc-issuer/version"
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:   "single-user-oidc-issuer",
	Short: "single-user-oidc-issuer, " + version.Version,
}
