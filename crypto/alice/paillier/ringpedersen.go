// Copyright © 2022 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package paillier

import (
	"math/big"

	zkPaillier "github.com/felicityin/mpc-tss/crypto/alice/zkproof/paillier"

	"github.com/felicityin/mpc-tss/crypto/alice/utils"
)

type (
	PedPubKey struct {
		N *big.Int
		S *big.Int
		T *big.Int
	}

	PedPrivKey struct {
		LambdaN *big.Int
		Euler   *big.Int
	}
)

type PederssenParameter struct {
	P      *big.Int
	Q      *big.Int
	Eulern *big.Int
	Lambda *big.Int

	PedersenOpenParameter *zkPaillier.PederssenOpenParameter
}

func (ped *PederssenParameter) Getlambda() *big.Int {
	return ped.Lambda
}

func (ped *PederssenParameter) GetP() *big.Int {
	return ped.P
}

func (ped *PederssenParameter) GetQ() *big.Int {
	return ped.Q
}

func (ped *PederssenParameter) GetEulerValue() *big.Int {
	return ped.Eulern
}

// By paillier
func (paillier *Paillier) NewPedersenParameterByPaillier() (*PederssenParameter, error) {
	eulern, err := utils.EulerFunction([]*big.Int{paillier.PrivateKey.P, paillier.PrivateKey.Q})
	n := paillier.PublicKey.N
	if err != nil {
		return nil, err
	}
	lambda, err := utils.RandomInt(eulern)
	if err != nil {
		return nil, err
	}
	tau, err := utils.RandomInt(n)
	if err != nil {
		return nil, err
	}
	t := new(big.Int).Exp(tau, big2, n)
	s := new(big.Int).Exp(t, lambda, n)
	return &PederssenParameter{
		P:                     paillier.PrivateKey.P,
		Q:                     paillier.PrivateKey.Q,
		Eulern:                eulern,
		Lambda:                lambda,
		PedersenOpenParameter: zkPaillier.NewPedersenOpenParameter(n, s, t),
	}, nil
}

func NewPedersenOpenParameter(n, s, t *big.Int) (*zkPaillier.PederssenOpenParameter, error) {
	if !utils.IsRelativePrime(s, n) {
		return nil, ErrInvalidInput
	}
	if !utils.IsRelativePrime(t, n) {
		return nil, ErrInvalidInput
	}
	if n.BitLen() < safePubKeySize {
		return nil, ErrSmallPublicKeySize
	}
	return zkPaillier.NewPedersenOpenParameter(n, s, t), nil
}

func ToPaillierPubKeyWithSpecialG(ped *zkPaillier.PederssenOpenParameter) *PublicKey {
	// special g = 1+ n (ref. definition 2.2 in cggmp)
	n := ped.GetN()
	return &PublicKey{
		N:       n,
		G:       new(big.Int).Add(big1, n),
		NSquare: new(big.Int).Mul(n, n),
	}
}
