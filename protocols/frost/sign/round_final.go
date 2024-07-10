package sign

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/agl/ed25519/edwards25519"
	edwards "github.com/decred/dcrd/dcrec/edwards/v2"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/tss"
)

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	common.Logger.Infof("[sign] party: %d, round_final start", i)

	sumS := round.temp.si

	for j, Pj := range round.Parties().IDs() {
		round.ok[j] = true
		if j == i {
			continue
		}

		r2msg := round.temp.signRound2Messages[j].Content().(*SignRound2Message)
		zi := r2msg.UnmarshalS()

		ziGx, ziGy := round.EC().ScalarBaseMult(zi.Bytes())
		ziG := crypto.NewECPointNoCurveCheck(round.EC(), ziGx, ziGy)

		tmp := round.key.PubXj[j].ScalarMult(round.temp.c)
		tmp, err := tmp.Add(round.temp.Rj[j])
		if err != nil {
			return round.WrapError(fmt.Errorf("err: Rj + c * Xj: %s", err.Error()), Pj)
		}

		if hex.EncodeToString(ziG.X().Bytes()) != hex.EncodeToString(tmp.X().Bytes()) ||
			hex.EncodeToString(ziG.Y().Bytes()) != hex.EncodeToString(tmp.Y().Bytes()) {
			return round.WrapError(fmt.Errorf("err: Zj != Rj + c * Xj"), Pj)
		}

		sjBytes := bigIntToEncodedBytes(zi)
		var tmpSumS [32]byte
		edwards25519.ScMulAdd(&tmpSumS, sumS, bigIntToEncodedBytes(big.NewInt(1)), sjBytes)
		sumS = &tmpSumS
	}
	s := encodedBytesToBigInt(sumS)

	// save the signature for final output
	round.data.Signature = append(bigIntToEncodedBytes(round.temp.r)[:], bigIntToEncodedBytes(s)[:]...)
	round.data.R = round.temp.r.Bytes()
	round.data.S = s.Bytes()
	if round.temp.fullBytesLen == 0 {
		round.data.M = round.temp.m.Bytes()
	} else {
		var mBytes = make([]byte, round.temp.fullBytesLen)
		round.temp.m.FillBytes(mBytes)
		round.data.M = mBytes
	}

	pk := edwards.PublicKey{
		Curve: round.Params().EC(),
		X:     round.key.Pubkey.X(),
		Y:     round.key.Pubkey.Y(),
	}

	ok := edwards.Verify(&pk, round.data.M, round.temp.r, s)
	if !ok {
		return round.WrapError(fmt.Errorf("signature verification failed"))
	}
	common.Logger.Infof("party: %d, round 3 end", i)
	round.end <- round.data

	return nil
}

func (round *finalization) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}
