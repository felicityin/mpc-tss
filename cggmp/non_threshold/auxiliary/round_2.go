package auxiliary

import (
	"errors"
	"fmt"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/tss"

	"github.com/golang/protobuf/proto"
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

	for j, msg := range round.temp.auxRound1Messages {
		r1Msg := msg.Content().(*AuxRound1Message)
		round.temp.V[j] = r1Msg.Hash
	}

	prmProofBytes, err := proto.Marshal(round.temp.prmProof)
	if err != nil {
		return round.WrapError(fmt.Errorf("party: %d, marshal prm proof error: %s", i, err.Error()))
	}

	common.Logger.Infof("party: %d, round_2 broadcast", i)
	{
		msg := NewAuxRound2Message(
			round.PartyID(),
			round.temp.ssid,
			round.temp.srid,
			round.save.PaillierPKs[i],
			round.save.PedersenPKs[i],
			prmProofBytes,
			round.temp.rho,
			round.temp.u,
		)
		round.temp.auxRound2Messages[i] = msg
		round.out <- msg
	}

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*AuxRound2Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.auxRound2Messages {
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
