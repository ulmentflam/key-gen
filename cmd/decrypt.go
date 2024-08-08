// Package cmd
/*
Copyright © 2024 Evan Owen <admin@ulmentflam.com>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"key-gen/save"
	"key-gen/util"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt keys",
	Long: `Decrypt keys that were encrypted when generated. 
The default path is .key-gen in the user's home directory.`,
	Run: func(cmd *cobra.Command, args []string) {
		config, err := util.NewDecryptConfig(cmd.Flags())
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to parse decrypt flags with error: %v\n", err)
			return
		}
		decrypted, err := save.Decrypt(config.GlobalConfig.FilePath, config.GlobalConfig.Password)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to decrypt with error: %v\n", err)
			return
		}
		fmt.Println(string(decrypted))
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)
}
