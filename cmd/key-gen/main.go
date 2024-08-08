package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"

	"github.com/tyler-smith/go-bip39"

	"key-gen/bip44"
	"key-gen/save"
	"key-gen/util"
)

func main() {
	config := util.NewConfig()

	if config.Decrypt {
		// Decrypt the wallet
		decrypted, err := save.Decrypt(config.FilePath, config.Password)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to decrypt with error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(decrypted))
		return
	}

	// Generate a mnemonic for memorization or user-friendly seeds
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)

	var encryptionPassword = ""
	var password = config.Password
	if password == "" {
		password = util.RandString(32)
	}
	if config.EncryptMnemonic {
		encryptionPassword = password
	}

	// Generate a Bip44 compliant key manager
	km, err := bip44.NewKeyManager(mnemonic, encryptionPassword)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed creating BIP44 key with error: %v\n", err)
		os.Exit(1)
	}

	// Save the wallet to a file or 1Password
	if config.Save {
		newSave, err := save.NewSave(config)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed creating save with error: %v\n", err)
			os.Exit(1)
		}
		err = newSave.Save(context.Background(), config, km)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed saving key with error: %v\n", err)
			os.Exit(1)
		}
	}

	// Print the mnemonic and accounts to the console
	if !config.Hide && !config.Encrypt {
		fmt.Printf("\n%-18s \n", config.Name)
		out, err := km.ToPrettyString(config.Accounts, config.Compressed)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed outputting key with error: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(out)
	}

}
