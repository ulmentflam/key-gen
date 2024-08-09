// Package cmd
/*
Copyright © 2024 Evan Owen <admin@ulmentflam.com>
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "key-gen",
	Short: "Generate keys for various blockchains",
	Long:  `key-gen is a CLI tool to generate keys for various blockchains. It supports Bitcoin, Ethereum, and other blockchains.It supports saving keys to 1Password, and the file system in encrypted or unencrypted json. The keys are generated from a BIP32 seed and support BIP44, BIP49, and BIP84 derivation paths. This project has not and will not be audited by a security professional. Use at your own risk.`,

	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP("file", "f", "", "The path to save the keys or read the keys from (optional, required for decrypt)")
	rootCmd.PersistentFlags().StringP("password", "p", "", "Password for encryption (optional, required for encrypt/decrypt)")
	rootCmd.PersistentFlags().BoolP("suppress", "s", false, "Suppress the mnemonic and private keys from the output")

	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
