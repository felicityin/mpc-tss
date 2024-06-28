package auxiliary

import (
	"context"
	"errors"
	"io"
	"runtime"
	"time"

	"mpc_tss/common"
	"mpc_tss/crypto/paillier"
)

const (
	// Using a modulus length of 2048 is recommended in the GG18 spec
	paillierModulusLen = 2048
	// Ticker for printing log statements while generating primes/modulus
	logProgressTickInterval = 4 * time.Second
	// Safe big len using random for ssid
	SafeBitLen = 1024
)

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
