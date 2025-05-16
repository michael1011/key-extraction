package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/michael1011/key-extractor/seed"
)

var chainParams = &chaincfg.MainNetParams

func main() {
	extendedKey, _, err := seed.ReadAezeed(chainParams)
	if err != nil {
		log.Fatal(err)
	}

	keyRing := &seed.HDKeyRing{
		ExtendedKey: extendedKey,
		ChainParams: chainParams,
	}

	nodeKey, err := keyRing.NodePubKey()
	if err != nil {
		log.Fatal(err)
	}

	pubKey, err := nodeKey.ECPubKey()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Public key: %s\n", hex.EncodeToString(pubKey.SerializeCompressed()))

	privKey, err := nodeKey.ECPrivKey()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Private key: %s\n", hex.EncodeToString(privKey.Serialize()))
}
