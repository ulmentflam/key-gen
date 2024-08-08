package btc

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

type DecodedWIF struct {
	BTCWIF       *btcutil.WIF
	WIFString    string
	Address      string
	SegwitBech32 string
	SegwitNested string
	Taproot      string
}

// FromPrivateKey generates a wif, EVMAddress, SegwitBech32, SegwitNested, and Taproot EVMAddress from a private key
func FromPrivateKey(prvKey *btcec.PrivateKey, compress bool) (dwif *DecodedWIF, err error) {
	dwif = nil
	// generate the wif(wallet import format) string
	btcwif, err := btcutil.NewWIF(prvKey, &chaincfg.MainNetParams, compress)
	if err != nil {
		return dwif, err
	}
	wifString := btcwif.String()

	// generate a normal p2pkh EVMAddress
	serializedPubKey := btcwif.SerializePubKey()
	addressPubKey, err := btcutil.NewAddressPubKey(serializedPubKey, &chaincfg.MainNetParams)
	if err != nil {
		return dwif, err
	}
	address := addressPubKey.EncodeAddress()

	// generate a normal p2wkh EVMAddress from the pubkey hash
	witnessProg := btcutil.Hash160(serializedPubKey)
	addressWitnessPubKeyHash, err := btcutil.NewAddressWitnessPubKeyHash(witnessProg, &chaincfg.MainNetParams)
	if err != nil {
		return dwif, err
	}
	segwitBech32 := addressWitnessPubKeyHash.EncodeAddress()

	// generate an EVMAddress which is
	// backwards compatible to Bitcoin nodes running 0.6.0 onwards, but
	// allows us to take advantage of segwit's scripting improvements,
	// and malleability fixes.
	serializedScript, err := txscript.PayToAddrScript(addressWitnessPubKeyHash)
	if err != nil {
		return dwif, err
	}
	addressScriptHash, err := btcutil.NewAddressScriptHash(serializedScript, &chaincfg.MainNetParams)
	if err != nil {
		return dwif, err
	}
	segwitNested := addressScriptHash.EncodeAddress()

	// generate a Taproot EVMAddress
	tapKey := txscript.ComputeTaprootKeyNoScript(prvKey.PubKey())
	addressTaproot, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(tapKey), &chaincfg.MainNetParams)
	if err != nil {
		return dwif, err
	}
	taproot := addressTaproot.EncodeAddress()

	dwif = &DecodedWIF{
		BTCWIF:       btcwif,
		Address:      address,
		WIFString:    wifString,
		SegwitBech32: segwitBech32,
		SegwitNested: segwitNested,
		Taproot:      taproot,
	}

	return dwif, err
}
