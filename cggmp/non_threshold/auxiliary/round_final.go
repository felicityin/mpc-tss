package auxiliary

import (
	"errors"
	"fmt"

	"github.com/felicityin/mpc-tss/common"
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

	for j, msg := range round.temp.auxRound3Messages {
		if j == i {
			continue
		}

		common.Logger.Debugf("round_4 get proof")

		facProof, err := msg.Content().(*AuxRound3Message).UnmarshalFacProof()
		if err != nil {
			common.Logger.Errorf("[j: %d] unmarshal fac proof failed", j)
			return round.WrapError(fmt.Errorf("[j: %d] unmarshal fac proof failed", j))
		}

		if err := facProof.Verify(ProofParameter, round.temp.ssid, round.temp.rho,
			round.save.PaillierPKs[j].N, round.save.PedersenPKs[i]); err != nil {
			common.Logger.Errorf("verify prm proof failed, party: %d", j)
			return round.WrapError(err)
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
