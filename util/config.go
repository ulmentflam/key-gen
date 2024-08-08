package util

import (
	"flag"
	"fmt"
	"os"
)

const (
	DefaultAccounts = 1
	DefaultName     = "Generated Wallet"
)

type Config struct {
	Accounts              int
	Name                  string
	Compressed            bool
	Save                  bool
	EncryptMnemonic       bool
	Encrypt               bool
	Decrypt               bool
	Password              string
	FilePath              string
	OPServiceAccountToken string
	OPVaultID             string
	Hide                  bool
}

func NewConfig() Config {
	accounts := flag.Int("accounts", DefaultAccounts, "Number of accounts to generate")
	name := flag.String("name", DefaultName, "Name of the wallet")
	notCompressed := flag.Bool("not-compressed", false, "Don't compress the output keys")
	noSave := flag.Bool("no-save", false, "Don't save the wallet to a file or to 1Password")
	encryptMnemonic := flag.Bool("encrypt-mnemonic", false, "Encrypt the mnemonic with a password")
	encrypt := flag.Bool("encrypt", false, "Encrypt the wallet save with a password")
	decrypt := flag.Bool("decrypt", false, "Decrypt the wallet saved with a password")
	hide := flag.Bool("hide", false, "Hide the mnemonic and private keys from the output")

	password := flag.String("password", "", "Password for the wallet (optional)")
	filePath := flag.String("file", "", "Path to save or decrypt the wallet")

	opsat := flag.String("op-service-account-token", "", "1Password service account token (optional)")
	opvi := flag.String("op-vault-id", "", "1Password vault ID (optional)")

	flag.Parse()

	if *encrypt || *decrypt {
		if *password == "" {
			fmt.Println("A password is required for encryption and decryption")
			os.Exit(1)
		}
	}

	if *decrypt && *filePath == "" {
		fmt.Println("A file path is required for decryption")
		os.Exit(1)
	}

	if *opsat == "" {
		opsatENV := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
		opsat = &opsatENV
	}

	if *opvi == "" {
		opviENV := os.Getenv("OP_VAULT_ID")
		opvi = &opviENV
	}

	if *opvi == "" && *opsat != "" {
		fmt.Println("A one password vault id is required when using 1Password. Please set OP_VAULT_ID or pass --op-vault-id as a flag")
		os.Exit(1)
	}

	if *opvi != "" && *opsat == "" {
		fmt.Println("A one password service account token is required when using 1Password. Please set OP_SERVICE_ACCOUNT_TOKEN or pass --op-service-account-token as a flag")
		os.Exit(1)
	}

	if *noSave && *hide {
		fmt.Println("You can't hide the output and not save it")
		os.Exit(1)
	}

	save := !*noSave
	compressed := !*notCompressed

	return Config{
		Accounts:              *accounts,
		Name:                  *name,
		Compressed:            compressed,
		Save:                  save,
		EncryptMnemonic:       *encryptMnemonic,
		Encrypt:               *encrypt,
		Decrypt:               *decrypt,
		FilePath:              *filePath,
		Password:              *password,
		OPServiceAccountToken: *opsat,
		OPVaultID:             *opvi,
		Hide:                  *hide,
	}
}
