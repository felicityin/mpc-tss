// Copyright © 2020 AMIS Technologies
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

	"github.com/felicityin/mpc-tss/crypto/alice/utils"
)

func (msg *PubKeyMessage) ToPubkey() (*PublicKey, error) {
	err := msg.Proof.Verify()
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(msg.Proof.PublicKey)
	g := new(big.Int).SetBytes(msg.G)
	nSquare := new(big.Int).Mul(n, n)
	// ensure n is positive
	if n.Cmp(big0) <= 0 {
		return nil, ErrInvalidMessage
	}
	// ensure g is [2, nsquare) and g and nSquare are coprime
	err = utils.InRange(g, big2, nSquare)
	if err != nil {
		return nil, err
	}
	if !utils.IsRelativePrime(g, nSquare) {
		return nil, ErrInvalidMessage
	}

	return &PublicKey{
		N:       n,
		G:       g,
		Msg:     msg,
		NSquare: nSquare,
	}, nil
}
