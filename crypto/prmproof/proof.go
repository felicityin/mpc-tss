// Copyright © 2022 AMIS Technologies
//
// Refer: https://github.com/getamis/alice/blob/master/crypto/zkproof/paillier/ring_pedersenzkproof.go

package prmproof

import (
	"errors"
	"math/big"
	sync "sync"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto/alice/utils"
)

var (
	//ErrTooFewChallenge is returned if the times of challenge is too few.
	ErrTooFewChallenge = errors.New("the times of challenge are too few")
	//ErrVerifyFailure is returned if the verification is failure.
	ErrVerifyFailure = errors.New("the verification is failure")
)

const MINIMALCHALLENGE = 80

var (
	big0 = big.NewInt(0)
	big2 = big.NewInt(2)
)

func NewRingPederssenParameterMessage(ssidInfo []byte, eulerValue *big.Int, n *big.Int, s *big.Int, t *big.Int, lambda *big.Int, nubmerZkproof int) (*RingPederssenParameterMessage, error) {
	if nubmerZkproof < MINIMALCHALLENGE {
		return nil, ErrTooFewChallenge
	}

	A := make([][]byte, nubmerZkproof)
	Z := make([][]byte, nubmerZkproof)
	salt, err := utils.GenRandomBytes(128)
	if err != nil {
		return nil, err
	}

	errChs := make(chan error, nubmerZkproof*2)
	wg := sync.WaitGroup{}
	wg.Add(nubmerZkproof)

	for i := 0; i < nubmerZkproof; i++ {
		go func(i int) {
			defer wg.Done()
			// Sample ai in Z_{φ(N)} for i in {1,...,m}
			ai, err := utils.RandomInt(eulerValue)
			if err != nil {
				common.Logger.Errorf("%s", err.Error())
				errChs <- err
			}
			Ai := new(big.Int).Exp(t, ai, n)
			// ei = {0, 1}
			ei, err := utils.HashBytesToInt(salt, ssidInfo, n.Bytes(), s.Bytes(), t.Bytes(), Ai.Bytes())
			if err != nil {
				common.Logger.Errorf("%s", err.Error())
				errChs <- err
			}
			ei.Mod(ei, big2)
			// zi = ai+ei λ mod φ(N) for i in {1,...,m}
			zi := new(big.Int).Add(ai, new(big.Int).Mul(ei, lambda))
			zi.Mod(zi, eulerValue)
			A[i] = Ai.Bytes()
			Z[i] = zi.Bytes()
		}(i)
	}

	// Consume error channels; wait for goroutines
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return nil, err
	}

	result := &RingPederssenParameterMessage{
		Z:    Z,
		A:    A,
		N:    n.Bytes(),
		S:    s.Bytes(),
		T:    t.Bytes(),
		Salt: salt,
	}
	return result, nil
}

func (msg *RingPederssenParameterMessage) Verify(ssidInfo []byte) error {
	verifyTime := len(msg.A)
	if verifyTime < MINIMALCHALLENGE {
		return ErrTooFewChallenge
	}
	var err error
	n := new(big.Int).SetBytes(msg.N)
	s := new(big.Int).SetBytes(msg.S)
	t := new(big.Int).SetBytes(msg.T)
	A := msg.A
	Z := msg.Z

	errChs := make(chan error, verifyTime*4)
	wg := sync.WaitGroup{}
	wg.Add(verifyTime)

	for i := 0; i < verifyTime; i++ {
		go func(i int) {
			defer wg.Done()

			// check Ai \in Z_{n}^\ast and zi in [0,N).
			Ai := new(big.Int).SetBytes(A[i])
			err = utils.InRange(Ai, big0, n)
			if err != nil {
				common.Logger.Errorf("%s", err.Error())
				errChs <- err
			}
			if !utils.IsRelativePrime(Ai, n) {
				common.Logger.Errorf("%s", ErrVerifyFailure)
				errChs <- ErrVerifyFailure
			}
			zi := new(big.Int).SetBytes(Z[i])
			err = utils.InRange(zi, big0, n)
			if err != nil {
				common.Logger.Errorf("%s", err.Error())
				errChs <- err
			}

			// Check t^{zi}=Ai· s^{ei} mod N , for every i ∈ {1,..,m}.
			ei, err := utils.HashBytesToInt(msg.Salt, ssidInfo, n.Bytes(), s.Bytes(), t.Bytes(), A[i])
			if err != nil {
				common.Logger.Errorf("%s", err.Error())
				errChs <- err
			}
			ei.Mod(ei, big2)
			Asei := new(big.Int).Exp(s, ei, n)
			Asei.Mul(Asei, Ai)
			Asei.Mod(Asei, n)
			tzi := new(big.Int).Exp(t, zi, n)
			if tzi.Cmp(Asei) != 0 {
				common.Logger.Errorf("%s", ErrVerifyFailure)
				errChs <- ErrVerifyFailure
			}
		}(i)
	}

	// Consume error channels; wait for goroutines
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return err
	}
	return nil
}
