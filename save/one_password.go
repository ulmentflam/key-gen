package save

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/1password/onepassword-sdk-go"

	"key-gen/bip44"
	"key-gen/util"
)

type OPSaver struct {
	client  *onepassword.Client
	vaultID string
}

func NewOPSaver(config util.Config) (s *OPSaver, err error) {
	client, err := onepassword.NewClient(context.TODO(), onepassword.WithServiceAccountToken(config.OPServiceAccountToken), onepassword.WithIntegrationInfo("My 1Password Integration", "v1.0.0"))
	if err != nil {
		return nil, err
	}

	return &OPSaver{client: client, vaultID: config.OPVaultID}, err
}

func sections() []onepassword.ItemSection {
	return []onepassword.ItemSection{
		{
			ID:    "wallet",
			Title: "Wallet",
		},
		{
			ID:    "evmAccounts",
			Title: "EVM Accounts",
		},
		{
			ID:    "bitcoinAccounts",
			Title: "Bitcoin Accounts",
		},
	}
}

func itemField(id string, title string, value string, fieldType onepassword.ItemFieldType, sectionID string) onepassword.ItemField {
	return onepassword.ItemField{
		ID:        id,
		Title:     title,
		Value:     value,
		FieldType: fieldType,
		SectionID: &sectionID,
	}
}

func walletAddressItem(id string, title string, value string, sectionID string) onepassword.ItemField {
	return itemField(fmt.Sprintf("walletAddress%s", id), title, value, onepassword.ItemFieldTypeText, sectionID)
}

func walletPathItem(id string, title string, value string, sectionID string) onepassword.ItemField {
	return itemField(fmt.Sprintf("walletPath%s", id), title, value, onepassword.ItemFieldTypeText, sectionID)
}

func walletPrivateKeyItem(id string, title string, value string, sectionID string) onepassword.ItemField {
	return itemField(fmt.Sprintf("walletPrivateKey%s", id), title, value, onepassword.ItemFieldTypeConcealed, sectionID)
}

func (s *OPSaver) Save(ctx context.Context, config util.Config, manager *bip44.KeyManager) error {
	currentTime := time.Now()
	itemName := fmt.Sprintf("%s (%s)", config.Name, currentTime.Format(time.ANSIC))
	fmt.Printf("\n%-18s \n", "1Password")
	fmt.Println(strings.Repeat("-", 106))
	fmt.Printf("%-18s %s\n", "1Password Item Name:", itemName)

	//Save the data from the manager
	mk, err := manager.MainKey()
	if err != nil {
		return err
	}

	itemSections := sections()

	var fields []onepassword.ItemField

	for _, section := range itemSections {
		// Create the sections
		if section.ID == "wallet" {
			fields = append(fields, itemField("recoveryPhrase", "recovery phrase", manager.Mnemonic, onepassword.ItemFieldTypeConcealed, section.ID))
			if manager.Passphrase != "" {
				fields = append(fields, itemField("password", "mnemonic password", manager.Passphrase, onepassword.ItemFieldTypeConcealed, section.ID))
			}
			fields = append(fields, itemField("seed", "seed", fmt.Sprintf("%x", manager.Seed()), onepassword.ItemFieldTypeConcealed, section.ID))
			fields = append(fields, itemField("root key", "root key", mk.Base58Key(), onepassword.ItemFieldTypeConcealed, section.ID))
		}
		if section.ID == "evmAccounts" {
			for i := 0; i < config.Accounts; i++ {
				key, err := manager.Key(bip44.PurposeBIP44, bip44.CoinTypeEthereum, 0, 0, uint32(i))
				if err != nil {
					return err
				}
				fields = append(fields, walletAddressItem(fmt.Sprintf("EVMAddress%d", i), fmt.Sprintf("Address #%d", i+1), key.EVMAddress.Hex(), section.ID))
				fields = append(fields, walletPathItem(fmt.Sprintf("EVMPath%d", i), fmt.Sprintf("Path #%d", i+1), key.Path, section.ID))
				fields = append(fields, walletPrivateKeyItem(fmt.Sprintf("EVMPrivateKey%d", i), fmt.Sprintf("Private Key #%d", i+1), key.HexKey(), section.ID))
			}
		}
		if section.ID == "bitcoinAccounts" {
			for i := 0; i < config.Accounts; i++ {
				legacyKey, err := manager.Key(bip44.PurposeBIP44, bip44.CoinTypeBitcoin, 0, 0, uint32(i))
				if err != nil {
					return err
				}
				legacy, err := legacyKey.DecodeWIF(config.Compressed)
				if err != nil {
					return err
				}
				swnKey, err := manager.Key(bip44.PurposeBIP49, bip44.CoinTypeBitcoin, 0, 0, uint32(i))
				if err != nil {
					return err
				}
				swn, err := swnKey.DecodeWIF(config.Compressed)
				if err != nil {
					return err
				}
				swn32Key, err := manager.Key(bip44.PurposeBIP84, bip44.CoinTypeBitcoin, 0, 0, uint32(i))
				if err != nil {
					return err
				}
				swn32, err := swn32Key.DecodeWIF(config.Compressed)
				if err != nil {
					return err
				}
				tprKey, err := manager.Key(bip44.PurposeBIP86, bip44.CoinTypeBitcoin, 0, 0, uint32(i))
				if err != nil {
					return err
				}
				tpr, err := tprKey.DecodeWIF(config.Compressed)
				if err != nil {
					return err
				}

				fields = append(fields, walletAddressItem(fmt.Sprintf("BTCLegacy%d", i), fmt.Sprintf("Bitcoin Legacy(P2PKH, compresed) #%d", i+1), legacy.Address, section.ID))
				fields = append(fields, walletAddressItem(fmt.Sprintf("BTCSegWit%d", i), fmt.Sprintf("Bitcoin SegWit(P2WPKH-nested-in-P2SH) #%d", i+1), swn.SegwitNested, section.ID))
				fields = append(fields, walletAddressItem(fmt.Sprintf("BTCSegWit32%d", i), fmt.Sprintf("Bitcoin SegWit(P2WPKH, bech32) #%d", i+1), swn32.SegwitBech32, section.ID))
				fields = append(fields, walletAddressItem(fmt.Sprintf("BTCTaproot%d", i), fmt.Sprintf("Bitcoin Taproot(P2TR, bech32m) #%d", i+1), tpr.Taproot, section.ID))
				fields = append(fields, walletPrivateKeyItem(fmt.Sprintf("BTCWIF%d", i), fmt.Sprintf("Bitcoin WIF(Wallet Import Format) #%d", i+1), legacy.WIFString, section.ID))
			}
		}
	}

	item := onepassword.ItemCreateParams{
		Title:    fmt.Sprintf("%s (%s)", config.Name, currentTime.Format(time.ANSIC)),
		VaultID:  s.vaultID,
		Category: onepassword.ItemCategoryCryptoWallet,
		Fields:   fields,
		Sections: itemSections,
	}
	newItem, err := s.client.Items.Create(ctx, item)
	if err != nil {
		return err
	}
	fmt.Printf("%-18s %s\n", "1Password ItemID:", newItem.ID)

	return nil
}
