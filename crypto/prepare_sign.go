// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/felicityin/mpc-tss/common"
)

func PrepareForSigning(
	ec elliptic.Curve,
	i, pax int,
	privXi *big.Int,
	ks []*big.Int,
	pubXj []*ECPoint,
) (wi *big.Int, bigWs []*ECPoint, sumW *ECPoint, err error) {
	modQ := common.ModInt(ec.Params().N)
	if len(ks) != len(pubXj) {
		err = fmt.Errorf("PrepareForSigning: len(ks) != len(bigXs) (%d != %d)", len(ks), len(pubXj))
		return
	}
	if len(ks) != pax {
		err = fmt.Errorf("PrepareForSigning: len(ks) != pax (%d != %d)", len(ks), pax)
		return
	}
	if len(ks) <= i {
		err = fmt.Errorf("PrepareForSigning: len(ks) <= i (%d <= %d)", len(ks), i)
		return
	}

	// 2-4.
	wi = new(big.Int).Set(privXi)
	for j := 0; j < pax; j++ {
		if j == i {
			continue
		}
		ksj := ks[j]
		ksi := ks[i]
		if ksj.Cmp(ksi) == 0 {
			common.Logger.Errorf("index of two parties are equal: (%d, %d), (%d, %d)", i, j, ksi, ksj)
			err = fmt.Errorf("index of two parties are equal")
			return
		}
		// big.Int Div is calculated as: a/b = a * modInv(b,q)
		coef := modQ.Mul(ks[j], modQ.ModInverse(new(big.Int).Sub(ksj, ksi)))
		wi = modQ.Mul(wi, coef)
	}

	// 5-10.
	bigWs = make([]*ECPoint, len(ks))
	for j := 0; j < pax; j++ {
		bigWj := pubXj[j]
		for c := 0; c < pax; c++ {
			if j == c {
				continue
			}
			ksc := ks[c]
			ksj := ks[j]
			if ksj.Cmp(ksc) == 0 {
				err = fmt.Errorf("index of two parties are equal")
				return
			}
			// big.Int Div is calculated as: a/b = a * modInv(b,q)
			iota := modQ.Mul(ksc, modQ.ModInverse(new(big.Int).Sub(ksc, ksj)))
			bigWj = bigWj.ScalarMult(iota)
		}
		bigWs[j] = bigWj
	}

	pubKey := bigWs[0]
	for j, pubx := range bigWs {
		if j == 0 {
			continue
		}
		pubKey, err = pubKey.Add(pubx)
		if err != nil {
			err = fmt.Errorf("calc pubkey failed, party: %d, %s", j, err.Error())
			return
		}
	}
	return wi, bigWs, pubKey, nil
}
