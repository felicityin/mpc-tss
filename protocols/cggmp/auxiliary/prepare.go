// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package auxiliary

import (
	"io"
	"math/big"
	"time"

	"github.com/felicityin/mpc-tss/common/pool"
	"github.com/felicityin/mpc-tss/common/sample"
	"github.com/felicityin/mpc-tss/crypto/paillier"
)

var big1 = big.NewInt(1)

const (
	// Using a modulus length of 2048 is recommended in the GG18 spec
	paillierModulusLen = 2048
	// Ticker for printing log statements while generating primes/modulus
	logProgressTickInterval = 4 * time.Second
	// Safe big len using random for ssid
	SafeBitLen = 1024
)

func GeneratePaillier(rand io.Reader) (*paillier.PrivateKey, error) {
	pl := pool.NewPool(0)
	P, Q := sample.Paillier(rand, pl)
	N := new(big.Int).Mul(P, Q)

	// phiN = P-1 * Q-1
	PMinus1, QMinus1 := new(big.Int).Sub(P, big1), new(big.Int).Sub(Q, big1)
	phiN := new(big.Int).Mul(PMinus1, QMinus1)

	// lambdaN = lcm(P−1, Q−1)
	gcd := new(big.Int).GCD(nil, nil, PMinus1, QMinus1)
	lambdaN := new(big.Int).Div(phiN, gcd)

	publicKey := &paillier.PublicKey{N: N}
	privateKey := &paillier.PrivateKey{PublicKey: *publicKey, LambdaN: lambdaN, PhiN: phiN, P: P, Q: Q}
	return privateKey, nil
}
