package util

import (
	"fmt"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	DefaultAccounts = 1
	DefaultName     = "Generated Wallet"
)

type GlobalConfig struct {
	Password       string
	FilePath       string
	SuppressOutput bool
}

type DecryptConfig struct {
	GlobalConfig *GlobalConfig
}

type OPConfig struct {
	ServiceAccountToken string
	VaultID             string
}

type KeyConfig struct {
	GlobalConfig    *GlobalConfig
	Mnemonic        string
	Accounts        int
	Name            string
	EncryptMnemonic bool
	Compressed      bool
	Encrypt         bool
	OPConfig        *OPConfig
}

type GenerateConfig struct {
	KeyConfig *KeyConfig
	Save      bool
}

func NewGlobalConfig(flagSet *pflag.FlagSet) (*GlobalConfig, error) {
	password, err := flagSet.GetString("password")
	if err != nil {
		return nil, err
	}

	filePath, err := flagSet.GetString("file")
	if err != nil {
		return nil, err
	}

	suppressOutput, err := flagSet.GetBool("suppress")
	if err != nil {
		return nil, err
	}
	return &GlobalConfig{
		Password:       password,
		FilePath:       filePath,
		SuppressOutput: suppressOutput,
	}, nil
}

func NewOPConfig(flagSet *pflag.FlagSet) (*OPConfig, error) {
	viper.AutomaticEnv()

	serviceAccountToken := viper.GetString("service_account_token")
	vaultID := viper.GetString("vault_id")

	if serviceAccountToken != "" && vaultID == "" {
		return nil, fmt.Errorf("a vault id is required when using a service account token")
	}

	return &OPConfig{
		ServiceAccountToken: serviceAccountToken,
		VaultID:             vaultID,
	}, nil
}

func NewKeyConfig(flagSet *pflag.FlagSet, encrypt bool) (*KeyConfig, error) {
	globalConfig, err := NewGlobalConfig(flagSet)
	if err != nil {
		return nil, err
	}

	mnemonic, err := flagSet.GetString("mnemonic")
	if err != nil {
		return nil, err
	}

	accounts, err := flagSet.GetInt("accounts")
	if err != nil {
		return nil, err
	}

	name, err := flagSet.GetString("name")
	if err != nil {
		return nil, err
	}

	encryptMnemonic, err := flagSet.GetBool("encrypt-mnemonic")
	if err != nil {
		return nil, err
	}

	compressed, err := flagSet.GetBool("compressed")
	if err != nil {
		return nil, err
	}

	if encryptMnemonic && globalConfig.Password == "" {
		return nil, fmt.Errorf("a password is required to encrypt the mnemonic")
	}

	opConfig, err := NewOPConfig(flagSet)
	if err != nil {
		return nil, err
	}

	if opConfig.ServiceAccountToken != "" && opConfig.VaultID == "" {
		return nil, fmt.Errorf("a vault id is required when using a service account token")
	}

	if opConfig.ServiceAccountToken == "" || opConfig.VaultID == "" {
		opConfig = nil
	}

	if encrypt {
		opConfig = nil
	}

	return &KeyConfig{
		GlobalConfig:    globalConfig,
		Mnemonic:        mnemonic,
		Accounts:        accounts,
		Name:            name,
		EncryptMnemonic: encryptMnemonic,
		Encrypt:         encrypt,
		Compressed:      compressed,
		OPConfig:        opConfig,
	}, nil
}

func NewGenerateConfig(flagSet *pflag.FlagSet) (*GenerateConfig, error) {

	generatorConfig, err := NewKeyConfig(flagSet, false)
	if err != nil {
		return nil, err
	}

	save, err := flagSet.GetBool("save")
	if err != nil {
		return nil, err
	}

	return &GenerateConfig{
		KeyConfig: generatorConfig,
		Save:      save,
	}, nil
}

func NewEncryptConfig(flagSet *pflag.FlagSet) (*KeyConfig, error) {
	keyConfig, err := NewKeyConfig(flagSet, true)
	if err != nil {
		return nil, err
	}
	if keyConfig.GlobalConfig.Password == "" {
		return nil, fmt.Errorf("a password is required for encryption")
	}
	return keyConfig, nil
}

func NewDecryptConfig(flagSet *pflag.FlagSet) (*DecryptConfig, error) {
	globalConfig, err := NewGlobalConfig(flagSet)
	if err != nil {
		return nil, err
	}
	if globalConfig.Password == "" {
		return nil, fmt.Errorf("a password is required for decryption")
	}
	if globalConfig.FilePath == "" {
		return nil, fmt.Errorf("a file path is required for decryption")
	}
	return &DecryptConfig{
		GlobalConfig: globalConfig,
	}, nil
}
