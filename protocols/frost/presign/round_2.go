package presign

import (
	"github.com/pkg/errors"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/protocols/frost/sign"
	"github.com/felicityin/mpc-tss/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("[sign] party: %d, round_2 start", i)

	for j, Pj := range round.Parties().IDs() {
		round.ok[j] = true
		if j == i {
			continue
		}

		r1msg := round.temp.signRound1Messages[j].Content().(*sign.SignRound1Message)

		D, err := r1msg.UnmarshalD()
		if err != nil {
			common.Logger.Errorf("failed to unmarshal D: %s, party: %d", err, j)
			return round.WrapError(errors.New("failed to unmarshal D"), Pj)
		}

		E, err := r1msg.UnmarshalE()
		if err != nil {
			common.Logger.Errorf("failed to unmarshal E: %s, party: %d", err, j)
			return round.WrapError(errors.New("failed to unmarshal E"), Pj)
		}

		round.save.DEs[j] = &DE{D, E}
	}

	round.end <- round.save
	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *round2) NextRound() tss.Round {
	return nil // finished!
}
