package signing

import (
	"fmt"
	"math/big"

	"github.com/felicityin/mpc-tss/protocols/cggmp/ecdsa/presign"
	"github.com/felicityin/mpc-tss/protocols/cggmp/keygen"
	"github.com/felicityin/mpc-tss/protocols/utils"
)

func PrepareForSigning(
	key *keygen.LocalPartySaveData,
	pre *presign.LocalPartySaveData,
	path string,
	isThreshold bool,
	threshold int,
) error {
	ec := key.Pubkey.Curve()
	keyDerivationDelta, _, err := utils.DerivingPubkeyFromPath(key.Pubkey, key.ChainCode.Bytes(), path, ec)
	if err != nil {
		return fmt.Errorf("there should not be an error deriving the child public key: %s", err.Error())
	}

	shift := new(big.Int).Set(keyDerivationDelta)
	shift = shift.Mul(shift, pre.K)
	pre.Chi.Add(pre.Chi, shift)

	err = utils.UpdateKeyForSigning(key, path, isThreshold, threshold)
	if err != nil {
		return err
	}
	return nil
}
