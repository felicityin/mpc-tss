package utils

import (
	"fmt"

	"github.com/felicityin/mpc-tss/protocols/cggmp/keygen"
)

func UpdateKeyForSigning(key *keygen.LocalPartySaveData, path string, isThreshold bool, threshold int) error {
	i, err := key.OriginalIndex()
	if err != nil {
		return fmt.Errorf("get party index err: %s", err.Error())
	}

	ec := key.Pubkey.Curve()

	if isThreshold {
		if threshold+1 > len(key.Ks) {
			return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", threshold+1, len(key.Ks))
		}

		key.PrivXi, key.PubXj, key.Pubkey, err = PrepareForSigning(ec, i, len(key.Ks), key.PrivXi, key.Ks, key.PubXj)
		if err != nil {
			return err
		}
	}

	if path == "" || path == "m" {
		return nil
	}

	keyDerivationDelta, extendedChildPk, err := DerivingPubkeyFromPath(key.Pubkey, key.ChainCode.Bytes(), path, ec)
	if err != nil {
		return fmt.Errorf("there should not be an error deriving the child public key: %s", err.Error())
	}

	err = UpdatePubkeyAndAdjustPubXj(key, keyDerivationDelta, extendedChildPk.PublicKey, ec)
	if err != nil {
		return fmt.Errorf("there should not be an error setting the derived keys: %s", err.Error())
	}

	if i == 0 {
		UpdatePrivkey(key, keyDerivationDelta, ec)
	}
	return nil
}
