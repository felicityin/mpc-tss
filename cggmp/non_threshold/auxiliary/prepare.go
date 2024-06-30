// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package auxiliary

import (
	"context"
	"errors"
	"io"
	"math/big"
	"runtime"
	"time"

	"mpc_tss/common"
	"mpc_tss/common/pool"
	"mpc_tss/common/sample"
	"mpc_tss/crypto/paillier"
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

// GeneratePreParams finds two safe primes and computes the Paillier secret required for the protocol.
// This can be a time consuming process so it is recommended to do it out-of-band.
// If not specified, a concurrency value equal to the number of available CPU cores will be used.
// If pre-parameters could not be generated before the context is done, an error is returned.
func GeneratePreParamsWithContextAndRandom(ctx context.Context, rand io.Reader, optionalConcurrency ...int) (*paillier.PrivateKey, error) {
	var concurrency int
	if 0 < len(optionalConcurrency) {
		if 1 < len(optionalConcurrency) {
			panic(errors.New("GeneratePreParams: expected 0 or 1 item in `optionalConcurrency`"))
		}
		concurrency = optionalConcurrency[0]
	} else {
		concurrency = runtime.NumCPU()
	}
	if concurrency /= 3; concurrency < 1 {
		concurrency = 1
	}

	// prepare for concurrent Paillier generation
	paiCh := make(chan *paillier.PrivateKey, 1)

	// generate Paillier public key E_i, private key and proof
	go func(ch chan<- *paillier.PrivateKey) {
		common.Logger.Info("generating the Paillier modulus, please wait...")
		start := time.Now()
		// more concurrency weight is assigned here because the paillier primes have a requirement of having "large" P-Q
		PiPaillierSk, _, err := paillier.GenerateKeyPair(ctx, rand, paillierModulusLen, concurrency*2)
		if err != nil {
			ch <- nil
			return
		}
		common.Logger.Infof("paillier modulus generated. took %s\n", time.Since(start))
		ch <- PiPaillierSk
	}(paiCh)

	// this ticker will print a log statement while the generating is still in progress
	logProgressTicker := time.NewTicker(logProgressTickInterval)

	// errors can be thrown in the following code; consume chans to end goroutines here
	var paiSK *paillier.PrivateKey
consumer:
	for {
		select {
		case <-logProgressTicker.C:
			common.Logger.Info("still generating primes...")
		case paiSK = <-paiCh:
			if paiSK == nil {
				return nil, errors.New("timeout or error while generating the Paillier secret key")
			}
			break consumer
		}
	}
	logProgressTicker.Stop()

	return paiSK, nil
}
