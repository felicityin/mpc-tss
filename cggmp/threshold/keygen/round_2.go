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
		if j == i {
			continue
		}
		r1Msg := msg.Content().(*TKgRound1Message)
		round.temp.V[j] = r1Msg.Hash
		round.temp.KGCs[j] = r1Msg.UnmarshalPolyCommitment()
	}

	// BROADCAST de-commitments
	common.Logger.Infof("party: %d, round_2 broadcast", i)
	{
		r2msg1 := NewKGRound2Message1(
			round.PartyID(),
			round.temp.ssid,
			round.temp.srid,
			round.temp.deCommitPolyG,
			round.temp.commitedA[i],
			round.temp.u,
			round.temp.chainCode,
		)
		round.temp.kgRound2Message1s[i] = r2msg1
		round.out <- r2msg1
	}

	// P2P send share ij to Pj
	shares := round.temp.shares
	for j, Pj := range round.Parties().IDs() {
		r2msg2 := NewKGRound2Message2(Pj, round.PartyID(), shares[j])
		// do not send to this Pj, but store for round 3
		if j == i {
			round.temp.kgRound2Message2s[j] = r2msg2
			continue
		}
		round.out <- r2msg2
	}

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*TKgRound2Message1); ok {
		return msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*TKgRound2Message2); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.kgRound2Message1s {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		msg2 := round.temp.kgRound2Message2s[j]
		if msg2 == nil || !round.CanAccept(msg2) {
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
