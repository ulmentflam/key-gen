// Package cmd
/*
Copyright © 2024 Evan Owen <admin@ulmentflam.com>
*/
package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"

	"key-gen/bip44"
	"key-gen/save"
	"key-gen/util"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Generate encrypted accounts with private keys to the file system",
	Long: `This command generates AES-256 encrypted accounts and keys to the file system at ~/.key-gen or a specified directory. 
It supports Bitcoin, Ethereum, and other blockchains that support BIP-0032 and BIP-0044 keys. 
It accepts or generates the base mnemonic and can encrypt the mnemonic with a password.`,
	Run: func(cmd *cobra.Command, args []string) {
		config, err := util.NewEncryptConfig(cmd.Flags())
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed creating generate config with error: %v\n", err)
			os.Exit(1)
		}
		mnemonic := config.Mnemonic
		if mnemonic == "" {
			// Generate a mnemonic for memorization or user-friendly seeds
			entropy, err := bip39.NewEntropy(256)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Failed creating entropy with error: %v\n", err)
				return
			}
			mnemonic, err = bip39.NewMnemonic(entropy)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Failed creating mnemonic with error: %v\n", err)
				return
			}
		}

		password := config.GlobalConfig.Password
		if !config.EncryptMnemonic {
			password = ""
		}

		// Generate a Bip44 compliant key manager
		km, err := bip44.NewKeyManager(mnemonic, password)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed creating BIP44 key with error: %v\n", err)
			return
		}

		newSave, err := save.NewSave(*config)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed creating save with error: %v\n", err)
			return
		}
		err = newSave.Save(context.Background(), km)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed saving key with error: %v\n", err)
			return
		}
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	encryptCmd.PersistentFlags().StringP("mnemonic", "m", "", "Base mnemonic for the wallet (optional)")
	encryptCmd.PersistentFlags().IntP("accounts", "a", util.DefaultAccounts, "Number of accounts to generate")
	encryptCmd.PersistentFlags().StringP("name", "n", util.DefaultName, "Name of the wallet")
	encryptCmd.PersistentFlags().BoolP("encrypt-mnemonic", "e", false, "Encrypt the mnemonic with a password")
	encryptCmd.PersistentFlags().BoolP("compressed", "c", true, "Compress the output keys")
}
