package presign

import (
	"errors"
	"math/big"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/protocols/frost/sign"
	"github.com/felicityin/mpc-tss/tss"
)

// round 1 represents round 1 of the signing part of the EDDSA TSS spec
func newRound1(
	params *tss.Parameters,
	data *LocalPartySaveData,
	temp *localTempData,
	out chan<- tss.Message,
	end chan<- *LocalPartySaveData,
) tss.Round {
	return &round1{
		&base{params, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1},
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

	ids := round.Parties().IDs().Keys()
	round.save.Ks = ids
	round.save.ShareID = ids[i]

	round.temp.ssidNonce = new(big.Int).SetUint64(0)
	var err error
	round.temp.ssid, err = round.getSSID()
	if err != nil {
		return round.WrapError(err)
	}

	d := common.GetRandomPositiveInt(round.Rand(), round.Params().EC().Params().N)
	e := common.GetRandomPositiveInt(round.Rand(), round.Params().EC().Params().N)

	D := crypto.ScalarBaseMult(round.EC(), d)
	E := crypto.ScalarBaseMult(round.EC(), e)

	round.save.DEs[i] = &DE{D, E}
	round.save.D = d
	round.save.E = e

	// broadcast
	common.Logger.Debugf("P[%d]: round_1 broadcast", i)
	r1msg, err := sign.NewSignRound1Message(round.PartyID(), D, E)
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
	if _, ok := msg.Content().(*sign.SignRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
