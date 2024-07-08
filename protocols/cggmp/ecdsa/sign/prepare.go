// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package sign

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
)

func PrepareForSigning(
	ec elliptic.Curve,
	i, pax int,
	privXi *big.Int,
	ks []*big.Int,
	pubXj []*crypto.ECPoint,
) (wi *big.Int, bigWs []*crypto.ECPoint) {
	modQ := common.ModInt(ec.Params().N)
	if len(ks) != len(pubXj) {
		panic(fmt.Errorf("PrepareForSigning: len(ks) != len(bigXs) (%d != %d)", len(ks), len(pubXj)))
	}
	if len(ks) != pax {
		panic(fmt.Errorf("PrepareForSigning: len(ks) != pax (%d != %d)", len(ks), pax))
	}
	if len(ks) <= i {
		panic(fmt.Errorf("PrepareForSigning: len(ks) <= i (%d <= %d)", len(ks), i))
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
			panic(fmt.Errorf("index of two parties are equal"))
		}
		// big.Int Div is calculated as: a/b = a * modInv(b,q)
		coef := modQ.Mul(ks[j], modQ.ModInverse(new(big.Int).Sub(ksj, ksi)))
		wi = modQ.Mul(wi, coef)
	}

	// 5-10.
	bigWs = make([]*crypto.ECPoint, len(ks))
	for j := 0; j < pax; j++ {
		bigWj := pubXj[j]
		for c := 0; c < pax; c++ {
			if j == c {
				continue
			}
			ksc := ks[c]
			ksj := ks[j]
			if ksj.Cmp(ksc) == 0 {
				panic(fmt.Errorf("index of two parties are equal"))
			}
			// big.Int Div is calculated as: a/b = a * modInv(b,q)
			iota := modQ.Mul(ksc, modQ.ModInverse(new(big.Int).Sub(ksc, ksj)))
			bigWj = bigWj.ScalarMult(iota)
		}
		bigWs[j] = bigWj
	}
	return
}
