// Copyright © 2021 Swingby

package utils

import (
	"crypto/elliptic"
	"math/big"

	"github.com/btcsuite/btcd/chaincfg"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/crypto/ckd"
	"github.com/felicityin/mpc-tss/protocols/cggmp/keygen"
)

func UpdatePubkeyAndAdjustPubXj(key *keygen.LocalPartySaveData, keyDerivationDelta *big.Int, extendedChildPk *crypto.ECPoint, ec elliptic.Curve) error {
	var err error
	gDelta := crypto.ScalarBaseMult(ec, keyDerivationDelta)
	key.Pubkey = extendedChildPk
	key.PubXj[0], err = key.PubXj[0].Add(gDelta)
	if err != nil {
		return err
	}
	return nil
}

func UpdatePrivkey(key *keygen.LocalPartySaveData, keyDerivationDelta *big.Int, ec elliptic.Curve) {
	mod := common.ModInt(ec.Params().N)
	key.PrivXi = mod.Add(keyDerivationDelta, key.PrivXi)
}

func DerivingPubkeyFromPath(
	masterPub *crypto.ECPoint, chainCode []byte, path string, ec elliptic.Curve,
) (keyDerivationDelta *big.Int, extendedParentPk *ckd.ExtendedKey, err error) {
	walletPath, err := ckd.ConvertPath(path)
	if err != nil {
		return
	}
	net := &chaincfg.MainNetParams
	extendedParentPk = &ckd.ExtendedKey{
		PublicKey:  masterPub,
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  chainCode[:],
		ParentFP:   []byte{0x00, 0x00, 0x00, 0x00},
		Version:    net.HDPrivateKeyID[:],
	}
	return ckd.DeriveChildKeyFromHierarchy(walletPath, extendedParentPk, ec.Params().N, ec)
}
