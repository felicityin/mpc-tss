package keygen

import (
	"errors"
	"math/big"
	"strconv"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	save "github.com/felicityin/mpc-tss/protocols/cggmp/keygen"
	"github.com/felicityin/mpc-tss/tss"
)

// round 1 represents round 1 of the keygen part of the EDDSA TSS spec
func newRound1(params *tss.Parameters, save *save.LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- *save.LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, save, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1},
	}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round 1 already started"))
	}
	round.number = 1
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	common.Logger.Infof("party: %d, round_1 start", i)

	round.temp.ssidNonce = new(big.Int).SetUint64(0)
	ssid, err := round.getSSID()
	if err != nil {
		return round.WrapError(err)
	}
	round.temp.ssid = ssid

	if round.save.PrivXi == nil {
		round.save.PrivXi = common.GetRandomPositiveInt(round.PartialKeyRand(), round.Params().EC().Params().N)
	}
	round.save.PubXj[i] = crypto.ScalarBaseMult(round.EC(), round.save.PrivXi)

	round.temp.tau = common.GetRandomPositiveInt(round.PartialKeyRand(), round.Params().EC().Params().N)
	round.temp.commitedA = crypto.ScalarBaseMult(round.EC(), round.temp.tau)

	round.temp.chainCode, _ = common.GetRandomBytes(round.Rand(), 32)
	round.temp.u, _ = common.GetRandomBytes(round.Rand(), 32)
	round.temp.srid, _ = common.GetRandomBytes(round.Rand(), 32)

	ids := round.Parties().IDs().Keys()
	round.save.Ks = ids
	round.save.ShareID = ids[i]

	// Compute V_i
	hash := common.SHA512_256(
		ssid,
		[]byte(strconv.Itoa(i)),
		round.temp.srid,
		round.save.PubXj[i].X().Bytes(),
		round.save.PubXj[i].Y().Bytes(),
		round.temp.commitedA.X().Bytes(),
		round.temp.commitedA.Y().Bytes(),
		round.temp.u,
		round.temp.chainCode,
	)

	common.Logger.Infof("party: %d, round_1 broadcast", i)

	// BROADCAST commitments
	{
		msg := NewKGRound1Message(round.PartyID(), hash)
		round.temp.kgRound1Messages[i] = msg
		round.out <- msg
	}
	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.kgRound1Messages {
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

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
