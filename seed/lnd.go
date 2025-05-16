package seed

import (
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightningnetwork/lnd/keychain"
)

const (
	HardenedKeyStart = uint32(hdkeychain.HardenedKeyStart)
)

type HDKeyRing struct {
	ExtendedKey *hdkeychain.ExtendedKey
	ChainParams *chaincfg.Params
}

func DeriveChildren(key *hdkeychain.ExtendedKey, path []uint32) (
	*hdkeychain.ExtendedKey, error) {

	var currentKey = key
	for idx, pathPart := range path {
		derivedKey, err := currentKey.DeriveNonStandard(pathPart)
		if err != nil {
			return nil, err
		}

		// There's this special case in lnd's wallet (btcwallet) where
		// the coin type and account keys are always serialized as a
		// string and encrypted, which actually fixes the key padding
		// issue that makes the difference between DeriveNonStandard and
		// Derive. To replicate lnd's behavior exactly, we need to
		// serialize and de-serialize the extended key at the coin type
		// and account level (depth = 2 or depth = 3). This does not
		// apply to the default account (id = 0) because that is always
		// derived directly.
		depth := derivedKey.Depth()
		keyID := pathPart - hdkeychain.HardenedKeyStart
		nextID := uint32(0)
		if depth == 2 && len(path) > 2 {
			nextID = path[idx+1] - hdkeychain.HardenedKeyStart
		}
		if (depth == 2 && nextID != 0) || (depth == 3 && keyID != 0) {
			currentKey, err = hdkeychain.NewKeyFromString(
				derivedKey.String(),
			)
			if err != nil {
				return nil, err
			}
		} else {
			currentKey = derivedKey
		}
	}
	return currentKey, nil
}

func (r *HDKeyRing) DeriveKey(keyLoc keychain.KeyLocator) (
	*hdkeychain.ExtendedKey, error) {

	derivedKey, err := DeriveChildren(r.ExtendedKey, []uint32{
		HardenedKeyStart + uint32(keychain.BIP0043Purpose),
		HardenedKeyStart + r.ChainParams.HDCoinType,
		HardenedKeyStart + uint32(keyLoc.Family),
		0,
		keyLoc.Index,
	})
	if err != nil {
		return nil, err
	}

	return derivedKey, nil
}

func (r *HDKeyRing) NodePubKey() (*hdkeychain.ExtendedKey, error) {
	key, err := r.DeriveKey(keychain.KeyLocator{
		Family: keychain.KeyFamilyNodeKey,
		Index:  0,
	})
	if err != nil {
		return nil, err
	}

	return key, nil
}
