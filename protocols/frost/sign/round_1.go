package sign

import (
	"errors"
	"math/big"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/protocols/cggmp/keygen"
	"github.com/felicityin/mpc-tss/tss"
)

// round 1 represents round 1 of the signing part of the EDDSA TSS spec
func newRound1(
	isThreshold bool,
	params *tss.Parameters,
	key *keygen.LocalPartySaveData,
	data *common.SignatureData,
	temp *localTempData,
	out chan<- tss.Message,
	end chan<- *common.SignatureData,
) tss.Round {
	return &round1{
		&base{params, isThreshold, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1},
	}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 1
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	common.Logger.Infof("[sign] party: %d, round_1 start", i)

	round.temp.ssidNonce = new(big.Int).SetUint64(0)
	var err error
	round.temp.ssid, err = round.getSSID()
	if err != nil {
		return round.WrapError(err)
	}

	round.temp.d = common.GetRandomPositiveInt(round.Rand(), round.Params().EC().Params().N)
	round.temp.e = common.GetRandomPositiveInt(round.Rand(), round.Params().EC().Params().N)

	D := crypto.ScalarBaseMult(round.EC(), round.temp.d)
	E := crypto.ScalarBaseMult(round.EC(), round.temp.e)

	// broadcast
	common.Logger.Debugf("P[%d]: round_1 broadcast", i)
	r1msg, err := NewSignRound1Message(round.PartyID(), D, E)
	if err != nil {
		return round.WrapError(err)
	}
	round.temp.signRound1Messages[i] = r1msg
	round.out <- r1msg

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound1Messages {
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

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
