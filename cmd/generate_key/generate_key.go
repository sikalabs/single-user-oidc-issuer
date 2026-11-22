package generate_key

import (
	"fmt"

	"github.com/sikalabs/single-user-oidc-issuer/cmd/root"
	"github.com/sikalabs/single-user-oidc-issuer/internal/oidc"
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:   "generate-key",
	Short: "Generate RSA private key (PEM) for signing tokens",
	Long: `Generate RSA private key (PEM) for signing tokens.

Use the output as PRIVATE_KEY (or save it to a file and use PRIVATE_KEY_FILE)
to keep the signing key stable across restarts.`,
	Args: cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		pem, err := oidc.GeneratePrivateKeyPEM()
		if err != nil {
			return err
		}
		fmt.Print(pem)
		return nil
	},
}

func init() {
	root.Cmd.AddCommand(Cmd)
}
