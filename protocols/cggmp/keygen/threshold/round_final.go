package keygen

import (
	"errors"
	"math/big"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto/schnorr"
	"github.com/felicityin/mpc-tss/tss"
)

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round 4 already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("party: %d, round_4 start", i)

	for j, msg := range round.temp.kgRound3Messages {
		if j == i {
			continue
		}

		common.Logger.Debugf("round_4 calc challenge")
		challenge := common.RejectionSample(
			round.EC().Params().N,
			common.SHA512_256i_TAGGED(
				append(round.temp.ssid, round.temp.srid...),
				big.NewInt(int64(j)),
				round.save.PubXj[j].X(),
				round.save.PubXj[j].Y(),
				round.temp.commitedA[j].X(),
				round.temp.commitedA[j].Y(),
			),
		)

		common.Logger.Debugf("round_4 get proof")

		schProof := schnorr.Proof{Proof: msg.Content().(*TKgRound3Message).UnmarshalSchProof()}

		common.Logger.Debugf("round_4 verify proof")

		if !schProof.Verify(round.temp.commitedA[j], round.save.PubXj[j], challenge) {
			common.Logger.Errorf("schnorr proof verify failed, party: %d", j)
			return round.WrapError(errors.New("schnorr proof verify failed"))
		}
	}

	common.Logger.Infof("party: %d, round_4 save", i)
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
