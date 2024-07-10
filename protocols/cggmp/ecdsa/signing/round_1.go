package signing

import (
	"errors"
	"math/big"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/protocols/cggmp/ecdsa/presign"
	"github.com/felicityin/mpc-tss/protocols/cggmp/ecdsa/sign"
	"github.com/felicityin/mpc-tss/protocols/cggmp/keygen"
	"github.com/felicityin/mpc-tss/tss"
)

var ProofParameter = crypto.NewProofConfig(tss.S256().Params().N)

// round 1 represents round 1 of the signing part of the EDDSA TSS spec
func newRound1(
	isThreshold bool,
	params *tss.Parameters,
	key *keygen.LocalPartySaveData,
	pre *presign.LocalPartySaveData,
	data *common.SignatureData,
	temp *localTempData,
	out chan<- tss.Message,
	end chan<- *common.SignatureData,
) tss.Round {
	return &round1{
		&base{params, isThreshold, key, pre, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1},
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

	round.temp.ssidNonce = new(big.Int).SetUint64(0)
	var err error
	round.temp.ssid, err = round.getSSID()
	if err != nil {
		return round.WrapError(err)
	}

	common.Logger.Infof("[sign] party: %d, round_1 start", i)

	modN := common.ModInt(round.EC().Params().N)
	round.temp.si = modN.Add(modN.Mul(round.pre.K, round.temp.msg), modN.Mul(round.pre.R.X(), round.pre.Chi))

	// broadcast sigma
	common.Logger.Debugf("P[%d]: broadcast sigma", i)
	r1msg := sign.NewSignRound4Message(round.PartyID(), round.temp.si)
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
	if _, ok := msg.Content().(*sign.SignRound4Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
