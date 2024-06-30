package keygen

import (
	"errors"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round 2 already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("party: %d, round_2 start", i)

	for j, msg := range round.temp.kgRound1Messages {
		r1Msg := msg.Content().(*KGRound1Message)
		round.temp.V[j] = r1Msg.Commitment
	}

	common.Logger.Infof("party: %d, round_2 broadcast", i)
	{
		msg := NewKGRound2Message(
			round.PartyID(),
			round.temp.ssid,
			round.temp.srid,
			round.save.PubXj[i],
			round.temp.commitedA,
			round.temp.u,
		)
		round.temp.kgRound2Messages[i] = msg
		round.out <- msg
	}

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound2Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.kgRound2Messages {
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

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
