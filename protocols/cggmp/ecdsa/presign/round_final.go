package presign

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/protocols/cggmp/ecdsa/sign"
	"github.com/felicityin/mpc-tss/tss"
)

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	common.Logger.Infof("[sign] party: %d, round4 start", i)

	sumDelta := new(big.Int).Set(round.temp.delta)
	sumBigDelta := round.temp.Delta

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		contextJ := append(round.temp.ssid, big.NewInt(int64(j)).Bytes()...)
		r3msg := round.temp.signRound3Messages[j].Content().(*sign.SignRound3Message)

		Delta, err := r3msg.UnmarshalBigDelta()
		if err != nil {
			return round.WrapError(fmt.Errorf("[j: %d] unmarshal big delta err: %s", j, err.Error()))
		}

		logProof, err := r3msg.UnmarshalLogProof()
		if err != nil {
			return round.WrapError(fmt.Errorf("[j: %d] unmarshal log proof err: %s", j, err.Error()))
		}
		if err = logProof.Verify(
			ProofParameter, contextJ, round.temp.kCiphertexts[j], round.aux.PaillierPKs[j].N,
			round.aux.PedersenPKs[i], Delta, round.temp.sumGamma,
		); err != nil {
			common.Logger.Errorf("[j: %d] verify log proof failed: %s, party: %d", j, err)
			return round.WrapError(fmt.Errorf("[j: %d] verify log proof failed: %s", j, err))
		}

		sumDelta.Add(sumDelta, r3msg.UnmarshalDelta())

		sumBigDelta, err = sumBigDelta.Add(Delta)
		if err != nil {
			return round.WrapError(err, Pj)
		}
	}

	gDelta := crypto.ScalarBaseMult(round.EC(), sumDelta)

	if hex.EncodeToString(gDelta.X().Bytes()) != hex.EncodeToString(sumBigDelta.X().Bytes()) ||
		hex.EncodeToString(gDelta.Y().Bytes()) != hex.EncodeToString(sumBigDelta.Y().Bytes()) {
		return round.WrapError(fmt.Errorf("verify delta failed"))
	}

	round.save.R = round.temp.sumGamma.ScalarMult(new(big.Int).ModInverse(sumDelta, round.EC().Params().N))

	round.end <- round.save
	return nil
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *round4) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *round4) NextRound() tss.Round {
	return nil // finished!
}
