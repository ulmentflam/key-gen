package bip44

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"

	"key-gen/btc"
)

type Key struct {
	Path       string
	BIP32Key   *bip32.Key
	Key        []byte
	EVMAddress common.Address
}

// NewKey creates a new Key from a BIP32 key
func NewKey(path string, key *bip32.Key) *Key {
	ecdaPrivateKey := crypto.ToECDSAUnsafe(key.Key)
	ecdaPublicKey := ecdaPrivateKey.Public().(*ecdsa.PublicKey)
	return &Key{
		path,
		key,
		key.Key,
		crypto.PubkeyToAddress(*ecdaPublicKey),
	}
}

// DecodeWIF decodes the key into a WIF
func (k *Key) DecodeWIF(compress bool) (*btc.DecodedWIF, error) {
	prvKey, _ := btcec.PrivKeyFromBytes(k.BIP32Key.Key)
	return btc.FromPrivateKey(prvKey, compress)
}

// HexKey returns the key as a hex string
func (k *Key) HexKey() string {
	return fmt.Sprintf("%x", k.Key)
}

// Base58Key returns the key as a base58 string bitcoin encoding
func (k *Key) Base58Key() string {
	return k.BIP32Key.B58Serialize()
}
