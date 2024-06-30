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

package mta

import (
	"fmt"
	"io"
	"math/big"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/crypto/affproof"
	pailliera "github.com/felicityin/mpc-tss/crypto/alice/paillier"
	"github.com/felicityin/mpc-tss/crypto/alice/utils"
	zkPaillier "github.com/felicityin/mpc-tss/crypto/alice/zkproof/paillier"
	"github.com/felicityin/mpc-tss/crypto/paillier"
	"github.com/felicityin/mpc-tss/tss"
)

var (
	big1         = big.NewInt(1)
	big2         = big.NewInt(2)
	parameter    = crypto.NewProofConfig(tss.S256().Params().N)
	curveNSquare = new(big.Int).Mul(parameter.CurveN, parameter.CurveN)
)

func MtaWithProofAff_g(
	rand io.Reader,
	ownssidwithbk []byte,
	peerPed *zkPaillier.PederssenOpenParameter,
	paillierKey *paillier.PublicKey,
	msgCipher *big.Int,
	x *big.Int,
	ecPoint *crypto.ECPoint,
) (*big.Int, *big.Int, *big.Int, *big.Int, []byte, *big.Int, *affproof.PaillierAffAndGroupRangeMessage, error) {
	beta, s, r, D, F, err := PerformMTA(rand, peerPed, paillierKey, msgCipher, x)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("perform mta err: %s", err.Error())
	}
	peerPaillierKey := pailliera.ToPaillierPubKeyWithSpecialG(peerPed)
	proof, err := affproof.NewPaillierAffAndGroupRangeMessage(
		parameter, ownssidwithbk, x, beta, s, r, peerPed.GetN(), paillierKey.N,
		msgCipher, D, F, peerPed, ecPoint,
	)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("create range proof err: %s", err.Error())
	}
	adjustBeta, count := computeBeta(beta, peerPaillierKey.GetN(), big.NewInt(0))
	return adjustBeta, count, r, s, D.Bytes(), F, proof, nil
}

func MtaWithProofAff_p(
	rand io.Reader,
	ownssidwithbk []byte,
	peerPed *zkPaillier.PederssenOpenParameter,
	paillierKey *paillier.PublicKey,
	msgKCipher *big.Int,
	gamma *big.Int,
	mu *big.Int,
	gammaCiphertext *big.Int,
) (*big.Int, *big.Int, *big.Int, *big.Int, *big.Int, *affproof.PaillierOperationAndCommitmentMessage, error) {
	beta, s, r, D, F, err := PerformMTA(rand, peerPed, paillierKey, msgKCipher, gamma)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	proof, err := affproof.NewPaillierOperationAndPaillierCommitment(
		parameter, ownssidwithbk, gamma, beta, s, mu, r, peerPed.GetN(), paillierKey.N,
		gammaCiphertext, F, msgKCipher, D, peerPed,
	)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	adjustBeta, _ := computeBeta(beta, peerPed.GetN(), big.NewInt(0))
	return adjustBeta, r, s, D, F, proof, nil
}

func PerformMTA(
	rand io.Reader,
	ped *zkPaillier.PederssenOpenParameter,
	paillierKey *paillier.PublicKey,
	msgCipher *big.Int,
	x *big.Int,
) (*big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
	beta, err := utils.RandomPositiveInt(new(big.Int).Lsh(big2, parameter.Lpai))
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	// Use other people pubKey: Dj,i = (γi ⊙ Kj) ⊕ encj(βi,j, si,j) and Fj,i = enci(βi,j, ri,j).
	peoplePaillierKey := pailliera.ToPaillierPubKeyWithSpecialG(ped)
	D := new(big.Int).Exp(msgCipher, x, peoplePaillierKey.GetNSquare())
	tempEnc, s, err := peoplePaillierKey.EncryptWithOutputSalt(beta)
	if err != nil {
		common.Logger.Errorf("ecrypt with output salt err: %s", err)
		return nil, nil, nil, nil, nil, err
	}
	D.Mul(D, tempEnc)
	D.Mod(D, peoplePaillierKey.GetNSquare())
	F, r, err := paillierKey.EncryptAndReturnRandomness(rand, beta)
	if err != nil {
		common.Logger.Errorf("ecrypt and return randomnes err: %s", err)
		return nil, nil, nil, nil, nil, err
	}
	return beta, s, r, D, F, nil
}

// If k*\gamma + beta < 0, we should change beta value.
func computeBeta(beta *big.Int, paillierN *big.Int, count *big.Int) (*big.Int, *big.Int) {
	result := new(big.Int).Neg(beta)
	if beta.Cmp(curveNSquare) < 0 {
		result.Sub(result, paillierN)
		count.Add(count, big1)
	}
	return result, count
}
