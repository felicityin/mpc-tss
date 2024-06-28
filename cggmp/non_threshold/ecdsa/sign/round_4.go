package sign

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"mpc_tss/common"
	"mpc_tss/crypto"
	"mpc_tss/tss"
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
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)

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

	round.temp.R = round.temp.sumGamma.ScalarMult(new(big.Int).ModInverse(sumDelta, round.EC().Params().N))

	modN := common.ModInt(round.EC().Params().N)
	round.temp.si = modN.Add(modN.Mul(round.temp.k, round.temp.msg), modN.Mul(round.temp.R.X(), round.temp.chi))

	// broadcast sigma
	common.Logger.Debugf("P[%d]: broadcast sigma", i)
	r4msg := NewSignRound4Message(round.PartyID(), round.temp.si)
	round.temp.signRound4Messages[i] = r4msg
	round.out <- r4msg

	return nil
}

func (round *round4) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound4Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound4Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round4) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
