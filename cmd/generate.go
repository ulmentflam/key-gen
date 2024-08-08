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
	"github.com/spf13/viper"
	"github.com/tyler-smith/go-bip39"

	"key-gen/bip44"
	"key-gen/save"
	"key-gen/util"
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate unencrypted accounts with private keys to 1Password and/or the file system",
	Long: `This command generates accounts and keys for various blockchains. 
It supports Bitcoin, Ethereum, and other blockchains that support BIP-0032 and BIP-0044 keys. 
It accepts or generates the base mnemonic and can encrypt the mnemonic with a password.`,
	Run: func(cmd *cobra.Command, args []string) {
		config, err := util.NewGenerateConfig(cmd.Flags())
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed creating generate config with error: %v\n", err)
			return
		}

		mnemonic := config.KeyConfig.Mnemonic
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

		password := config.KeyConfig.GlobalConfig.Password
		if !config.KeyConfig.EncryptMnemonic {
			password = ""
		}

		// Generate a Bip44 compliant key manager
		km, err := bip44.NewKeyManager(mnemonic, password)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed creating BIP44 key with error: %v\n", err)
			return
		}

		if config.Save {
			newSave, err := save.NewSave(*config.KeyConfig)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Failed creating save with error: %v\n", err)
				return
			}
			err = newSave.Save(context.Background(), km)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Failed saving key with error: %v\n", err)
				return
			}
		}

		if !config.KeyConfig.GlobalConfig.SuppressOutput {
			fmt.Printf("\n%-18s \n", config.KeyConfig.Name)
			out, err := km.ToPrettyString(config.KeyConfig.Accounts, config.KeyConfig.Compressed)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Failed outputting key with error: %v\n", err)
				return
			}
			fmt.Print(out)
		}

	},
}

func init() {
	rootCmd.AddCommand(generateCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// generateCmd.PersistentFlags().String("foo", "", "A help for foo")
	generateCmd.PersistentFlags().StringP("mnemonic", "m", "", "Base mnemonic for the wallet (optional)")
	generateCmd.PersistentFlags().IntP("accounts", "a", util.DefaultAccounts, "Number of accounts to generate")
	generateCmd.PersistentFlags().StringP("name", "n", util.DefaultName, "Name of the wallet")
	generateCmd.PersistentFlags().BoolP("encrypt-mnemonic", "e", false, "Encrypt the mnemonic with a password")
	generateCmd.PersistentFlags().BoolP("compressed", "c", true, "Compress the output keys")
	generateCmd.PersistentFlags().BoolP("save", "", true, "Save the wallet to a file or to 1Password")
	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// generateCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	viper.SetEnvPrefix("op")
	generateCmd.Flags().StringP("op-service-account-token", "t", "", "1Password service account token (optional)")
	generateCmd.Flags().StringP("op-vault-id", "v", "", "1Password vault ID (optional)")
	err := viper.BindPFlag("service_account_token", generateCmd.Flags().Lookup("op-service-account-token"))
	if err != nil {
		fmt.Println(err)
		return
	}
	err = viper.BindPFlag("vault_id", generateCmd.Flags().Lookup("op-vault-id"))
	if err != nil {
		fmt.Println(err)
		return
	}
}
