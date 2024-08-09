// Package bip44
/*
Copyright © 2024 Evan Owen <admin@ulmentflam.com>

Thanks to modood and tyler-smith for the reference implementation.
*/
package bip44

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// Purpose BIP43 - Purpose Field for Deterministic Wallets
// https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki
//
// Purpose is a constant set to 44' (or 0x8000002C) following the BIP43 recommendation.
// It indicates that the subtree of this node is used according to this specification.
//
// What does 44' mean in BIP44?
// https://bitcoin.stackexchange.com/questions/74368/what-does-44-mean-in-bip44
//
// 44' means that hardened keys should be used. The distinguisher for whether
// a key a given index is hardened is that the index is greater than 2^31,
// which is 2147483648. In hex, that is 0x80000000. That is what the apostrophe (') means.
// The 44 comes from adding it to 2^31 to get the final hardened key index.
// In hex, 44 is 2C, so 0x80000000 + 0x2C = 0x8000002C.
// Thanks to https://github.com/modood/hdkeygen/ for providing a reference implementation.
type Purpose uint32

const (
	PurposeBIP44 Purpose = 0x8000002C // 44' BIP44
	PurposeBIP49 Purpose = 0x80000031 // 49' BIP49
	PurposeBIP84 Purpose = 0x80000054 // 84' BIP84
	PurposeBIP86 Purpose = 0x80000056 // 86' BIP86
)

// CoinType SLIP-0044 : Registered coin types for BIP-0044
// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
type CoinType uint32

const (
	CoinTypeBitcoin         CoinType = 0x80000000 // 0' Bitcoin
	CoinTypeTestnet         CoinType = 0x80000001 // 1' Bitcoin Testnet
	CoinTypeLitecoin        CoinType = 0x80000002 // 2' Litecoin
	CoinTypeDogecoin        CoinType = 0x80000003 // 3' Dogecoin
	CoinTypeDash            CoinType = 0x80000005 // 5' Dash
	CoinTypeEthereum        CoinType = 0x8000003c // 60' Ethereum
	CoinTypeEthereumClassic CoinType = 0x8000003d // 61' Ethereum Classic
	CoinTypeBitcoinCash     CoinType = 0x80000091 // 145' Bitcoin Cash
	CoinTypeBitcoinSV       CoinType = 0x800000c9 // 201' Bitcoin SV
	CoinTypeLitecoinTestnet CoinType = 0x80000004 // 4' Litecoin Testnet
	CoinTypeDashTestnet     CoinType = 0x80000006 // 6' Dash Testnet
	CoinTypeBitcoinGold     CoinType = 0x8000009c // 156' Bitcoin Gold
	CoinTypeZcash           CoinType = 0x80000085 // 133' Zcash
	CoinTypeZcashTestnet    CoinType = 0x80000087 // 133' Zcash Testnet
	CoinTypeRavencoin       CoinType = 0x8000007a // 122' Ravencoin
	CoinTypeMonacoin        CoinType = 0x80000080 // 128' Monacoin
	CoinTypeDecred          CoinType = 0x8000002a // 42' Decred
	CoinTypeGroestlcoin     CoinType = 0x800000c0 // 192' Groestlcoin
	CoinTypeDigiByte        CoinType = 0x80000014 // 20' DigiByte
	CoinTypeQtum            CoinType = 0x8000002b // 43' Qtum
	CoinTypeViacoin         CoinType = 0x80000070 // 112' Viacoin
	CoinTypeBitcoinPrivate  CoinType = 0x800000cc // 204' Bitcoin Private
	CoinTypeBitcoinZ        CoinType = 0x800000b6 // 182' BitcoinZ
	CoinTypeHush            CoinType = 0x80000085 // 133' Hush
	CoinTypeZelcash         CoinType = 0x800000b8 // 184' Zelcash
	CoinTypeSnowGem         CoinType = 0x800000b7 // 183' SnowGem
	CoinTypeBitcore         CoinType = 0x8000000d // 13' Bitcore
	CoinTypeZenCash         CoinType = 0x80000020 // 32' ZenCash
	CoinTypePeercoin        CoinType = 0x80000066 // 102' Peercoin
	CoinTypeBitcoinAtom     CoinType = 0x8000009a // 154' Bitcoin Atom
	CoinTypeBitcoinInterest CoinType = 0x800000ce // 206' Bitcoin Interest
	CoinTypeBitcoinGreen    CoinType = 0x8000008c // 140' Bitcoin Green
	CoinTypeBitcoinPlus     CoinType = 0x80000066 // 102' Bitcoin Plus
	CoinTypeBitcoinDark     CoinType = 0x8000000e // 14' Bitcoin Dark
)

const Apostrophe uint32 = 0x80000000 // 0'

// https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
// bip44 define the following 5 levels in BIP32 path:
// m / purpose' / coin_type' / account' / change / address_index

// BIP44

type KeyManager struct {
	Mnemonic   string
	Passphrase string
	keys       map[string]*bip32.Key
	mux        sync.Mutex
}

// NewKeyManager return new key manager
// if mnemonic is not provided, it will generate a new mnemonic with 128 bits of entropy, which is 12 words
func NewKeyManager(mnemonic, passphrase string) (*KeyManager, error) {
	if mnemonic == "" {
		entropy, err := bip39.NewEntropy(128)
		if err != nil {
			return nil, err
		}
		mnemonic, err = bip39.NewMnemonic(entropy)
		if err != nil {
			return nil, err
		}
	}

	km := &KeyManager{
		Mnemonic:   mnemonic,
		Passphrase: passphrase,
		keys:       make(map[string]*bip32.Key, 0),
	}
	return km, nil
}

// Seed returns the seed for the given mnemonic and passphrase
func (km *KeyManager) Seed() []byte {
	return bip39.NewSeed(km.Mnemonic, km.Passphrase)
}

// GetKey returns the key for the given path
func (km *KeyManager) GetKey(path string) (*bip32.Key, bool) {
	km.mux.Lock()
	defer km.mux.Unlock()

	key, ok := km.keys[path]
	return key, ok
}

// SetKey sets the key for the given path
func (km *KeyManager) SetKey(path string, key *bip32.Key) {
	km.mux.Lock()
	defer km.mux.Unlock()

	km.keys[path] = key
}

// MainKey returns the main key
func (km *KeyManager) MainKey() (*Key, error) {
	path := "m"
	key, ok := km.GetKey(path)
	if ok {
		return NewKey(path, key), nil
	}
	key, err := bip32.NewMasterKey(km.Seed())
	if err != nil {
		return nil, err
	}
	km.SetKey(path, key)
	return NewKey(path, key), nil
}

// PurposeKey returns the purpose key
func (km *KeyManager) PurposeKey(purpose Purpose) (*Key, error) {
	path := fmt.Sprintf("m/%d'", uint32(purpose)-Apostrophe)

	key, ok := km.GetKey(path)
	if ok {
		return NewKey(path, key), nil
	}

	parent, err := km.MainKey()
	if err != nil {
		return nil, err
	}

	key, err = parent.BIP32Key.NewChildKey(uint32(purpose))
	if err != nil {
		return nil, err
	}

	km.SetKey(path, key)

	return NewKey(path, key), nil
}

// CoinTypeKey returns the coin type key
func (km *KeyManager) CoinTypeKey(purpose Purpose, coinType CoinType) (*Key, error) {
	path := fmt.Sprintf("m/%d'/%d'", uint32(purpose)-Apostrophe, uint32(coinType)-Apostrophe)

	key, ok := km.GetKey(path)
	if ok {
		return NewKey(path, key), nil
	}

	parent, err := km.PurposeKey(purpose)
	if err != nil {
		return nil, err
	}

	key, err = parent.BIP32Key.NewChildKey(uint32(coinType))
	if err != nil {
		return nil, err
	}

	km.SetKey(path, key)

	return NewKey(path, key), nil
}

// AccountKey returns the account key
func (km *KeyManager) AccountKey(purpose Purpose, coinType CoinType, account uint32) (*Key, error) {
	path := fmt.Sprintf("m/%d'/%d'/%d'", uint32(purpose)-Apostrophe, uint32(coinType)-Apostrophe, account)

	key, ok := km.GetKey(path)
	if ok {
		return NewKey(path, key), nil
	}

	parent, err := km.CoinTypeKey(purpose, coinType)
	if err != nil {
		return nil, err
	}

	key, err = parent.BIP32Key.NewChildKey(account)
	if err != nil {
		return nil, err
	}

	km.SetKey(path, key)

	return NewKey(path, key), nil
}

// ChangeKey ...
// https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#change
// change constant 0 is used for external chain
// change constant 1 is used for internal chain (also known as change addresses)
func (km *KeyManager) ChangeKey(purpose Purpose, coinType CoinType, account uint32, change uint32) (*Key, error) {
	path := fmt.Sprintf("m/%d'/%d'/%d'/%d", uint32(purpose)-Apostrophe, uint32(coinType)-Apostrophe, account, change)

	key, ok := km.GetKey(path)
	if ok {
		return NewKey(path, key), nil
	}

	parent, err := km.AccountKey(purpose, coinType, account)
	if err != nil {
		return nil, err
	}

	key, err = parent.BIP32Key.NewChildKey(change)
	if err != nil {
		return nil, err
	}

	km.SetKey(path, key)

	return NewKey(path, key), nil
}

// Key returns the key for the given path
func (km *KeyManager) Key(purpose Purpose, coinType CoinType, account uint32, change uint32, index uint32) (*Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'/%d'/%d/%d`, uint32(purpose)-Apostrophe, uint32(coinType)-Apostrophe, account, change, index)

	key, ok := km.GetKey(path)
	if ok {
		return NewKey(path, key), nil
	}

	parent, err := km.ChangeKey(purpose, coinType, account, change)
	if err != nil {
		return nil, err
	}

	key, err = parent.BIP32Key.NewChildKey(index)
	if err != nil {
		return nil, err
	}

	km.SetKey(path, key)

	return NewKey(path, key), nil
}

type KeyAccountJSON struct {
	Path       string `json:"path"`
	Address    string `json:"address"`
	PrivateKey string `json:"private_key"`
	KeyType    string `json:"type"`
}

type KeyManagerJSON struct {
	Mnemonic        string           `json:"recovery_phrase"`
	Passphrase      string           `json:"mnemonic_password"`
	Seed            string           `json:"seed"`
	RootKey         string           `json:"root_key"`
	EVMAccounts     []KeyAccountJSON `json:"evm_accounts"`
	BitcoinAccounts []KeyAccountJSON `json:"bitcoin_accounts"`
}

// ToJSON returns the key manager as a JSON string
func (km *KeyManager) ToJSON(accounts int, compress bool) (string, error) {
	mainKey, err := km.MainKey()
	if err != nil {
		return "", err
	}
	btcAccounts := make([]KeyAccountJSON, 0)
	evmAccounts := make([]KeyAccountJSON, 0)
	evmAccounts = append(evmAccounts, KeyAccountJSON{
		Path:       mainKey.Path,
		Address:    mainKey.EVMAddress.String(),
		PrivateKey: fmt.Sprintf("%x", mainKey.Key),
		KeyType:    "Ethereum(EIP55)",
	})
	mainWIF, err := mainKey.NewWIF(compress)
	if err != nil {
		return "", err
	}
	btcAccounts = append(btcAccounts, KeyAccountJSON{
		Path:       mainKey.Path,
		Address:    mainWIF.Address,
		PrivateKey: mainWIF.WIFString,
		KeyType:    "Legacy(P2PKH, compressed)",
	})
	for i := 0; i < accounts; i++ {
		legacyKey, err := km.Key(PurposeBIP44, CoinTypeBitcoin, 0, 0, uint32(i))
		if err != nil {
			return "", err
		}
		legacy, err := legacyKey.NewWIF(compress)
		if err != nil {
			return "", err
		}
		btcAccounts = append(btcAccounts, KeyAccountJSON{
			Path:       legacyKey.Path,
			Address:    legacy.Address,
			PrivateKey: legacy.WIFString,
			KeyType:    "Legacy(P2PKH, compressed)",
		})
		swnKey, err := km.Key(PurposeBIP49, CoinTypeBitcoin, 0, 0, uint32(i))
		if err != nil {
			return "", err
		}
		swn, err := swnKey.NewWIF(compress)
		if err != nil {
			return "", err
		}
		btcAccounts = append(btcAccounts, KeyAccountJSON{
			Path:       swnKey.Path,
			Address:    swn.Address,
			PrivateKey: swn.WIFString,
			KeyType:    "SegWit(P2WPKH-nested-in-P2SH)",
		})
		swn32Key, err := km.Key(PurposeBIP84, CoinTypeBitcoin, 0, 0, uint32(i))
		if err != nil {
			return "", err
		}
		swn32, err := swn32Key.NewWIF(compress)
		if err != nil {
			return "", err
		}
		btcAccounts = append(btcAccounts, KeyAccountJSON{
			Path:       swn32Key.Path,
			Address:    swn32.Address,
			PrivateKey: swn32.WIFString,
			KeyType:    "SegWit(P2WPKH, bech32)",
		})
		tprKey, err := km.Key(PurposeBIP86, CoinTypeBitcoin, 0, 0, uint32(i))
		if err != nil {
			return "", err
		}
		tpr, err := tprKey.NewWIF(compress)
		if err != nil {
			return "", err
		}
		btcAccounts = append(btcAccounts, KeyAccountJSON{
			Path:       tprKey.Path,
			Address:    tpr.Address,
			PrivateKey: tpr.WIFString,
			KeyType:    "Taproot(P2TR, bech32m)",
		})
		key, err := km.Key(PurposeBIP44, CoinTypeEthereum, 0, 0, uint32(i))
		if err != nil {
			return "", err
		}
		evmAccounts = append(evmAccounts, KeyAccountJSON{
			Path:       key.Path,
			Address:    key.EVMAddress.String(),
			PrivateKey: fmt.Sprintf("%x", key.Key),
			KeyType:    "Ethereum(EIP55)",
		})
	}
	kmj := &KeyManagerJSON{
		Mnemonic:        km.Mnemonic,
		Passphrase:      km.Passphrase,
		Seed:            fmt.Sprintf("%x", km.Seed()),
		RootKey:         mainKey.Base58Key(),
		BitcoinAccounts: btcAccounts,
		EVMAccounts:     evmAccounts,
	}
	b, err := json.Marshal(kmj)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (km *KeyManager) ToPrettyString(accounts int, compress bool) (sp string, err error) {
	sp = ""
	mainKey, err := km.MainKey()
	if err != nil {
		return "", err
	}

	passphrase := km.Passphrase
	if passphrase == "" {
		passphrase = "<none>"
	}
	sp += strings.Repeat("-", 200)
	sp += fmt.Sprintf("\n%-18s %s\n", "BIP39 Mnemonic:", km.Mnemonic)
	sp += fmt.Sprintf("%-18s %s\n", "BIP39 Passphrase:", passphrase)
	sp += fmt.Sprintf("%-18s %x\n", "BIP39 Seed:", km.Seed())
	sp += fmt.Sprintf("%-18s %s\n", "BIP32 Root BIP32Key:", mainKey.Base58Key())

	sp += fmt.Sprintf("\n%-18s %-34s %-52s\n", "Path(BIP44)", "Legacy(P2PKH, compressed)", "WIF(Wallet Import Format)")
	sp += strings.Repeat("-", 106)
	sp += "\n"
	wif, err := mainKey.NewWIF(compress)
	if err != nil {
		return "", err
	}
	sp += fmt.Sprintf("%-18s %-34s %s\n", mainKey.Path, wif.Address, wif.WIFString)

	for i := 0; i < accounts; i++ {
		key, err := km.Key(PurposeBIP44, CoinTypeBitcoin, 0, 0, uint32(i))
		if err != nil {
			return "", err
		}
		wif, err := key.NewWIF(compress)
		if err != nil {
			return "", err
		}

		sp += fmt.Sprintf("%-18s %-34s %s\n", key.Path, wif.Address, wif.WIFString)
	}

	sp += fmt.Sprintf("\n%-18s %-34s %s\n", "Path(BIP49)", "SegWit(P2WPKH-nested-in-P2SH)", "WIF(Wallet Import Format)")
	sp += strings.Repeat("-", 106)
	sp += "\n"
	for i := 0; i < accounts; i++ {
		key, err := km.Key(PurposeBIP49, CoinTypeBitcoin, 0, 0, uint32(i))
		if err != nil {
			return "", err
		}
		wif, err := key.NewWIF(compress)
		if err != nil {
			return "", err
		}

		sp += fmt.Sprintf("%-18s %s %s\n", key.Path, wif.SegwitNested, wif.WIFString)
	}

	sp += fmt.Sprintf("\n%-18s %-42s %s\n", "Path(BIP84)", "SegWit(P2WPKH, bech32)", "WIF(Wallet Import Format)")
	sp += strings.Repeat("-", 114)
	sp += "\n"
	for i := 0; i < accounts; i++ {
		key, err := km.Key(PurposeBIP84, CoinTypeBitcoin, 0, 0, uint32(i))
		if err != nil {
			return "", err
		}
		dwif, err := key.NewWIF(compress)
		if err != nil {
			return "", err
		}

		sp += fmt.Sprintf("%-18s %s %s\n", key.Path, dwif.SegwitBech32, dwif.WIFString)
	}

	sp += fmt.Sprintf("\n%-18s %-62s %s\n", "Path(BIP86)", "Taproot(P2TR, bech32m)", "WIF(Wallet Import Format)")
	sp += strings.Repeat("-", 134)
	sp += "\n"

	for i := 0; i < accounts; i++ {
		key, err := km.Key(PurposeBIP86, CoinTypeBitcoin, 0, 0, uint32(i))
		if err != nil {
			return "", err
		}
		wif, err := key.NewWIF(compress)
		if err != nil {
			return "", err
		}

		sp += fmt.Sprintf("%-18s %s %s\n", key.Path, wif.Taproot, wif.WIFString)
	}

	sp += fmt.Sprintf("\n%-18s %-42s %-52s\n", "Path(BIP44)", "Ethereum(EIP55)", "Private BIP32Key(hex)")
	sp += strings.Repeat("-", 126)
	sp += "\n"
	sp += fmt.Sprintf("%-18s %s %x\n", mainKey.Path, mainKey.EVMAddress, mainKey.Key)
	for i := 0; i < accounts; i++ {
		key, err := km.Key(PurposeBIP44, CoinTypeEthereum, 0, 0, uint32(i))
		if err != nil {
			return "", err
		}
		sp += fmt.Sprintf("%-18s %s %x\n", key.Path, key.EVMAddress, key.Key)
	}
	sp += "\n"
	return sp, nil
}
