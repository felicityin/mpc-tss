package sign

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/felicityin/mpc-tss/cggmp/threshold/keygen"
	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/tss"
)

// round 1 represents round 1 of the signing part of the EDDSA TSS spec
func newRound1(
	params *tss.Parameters,
	key *keygen.LocalPartySaveData,
	data *common.SignatureData,
	temp *localTempData,
	out chan<- tss.Message,
	end chan<- *common.SignatureData,
) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1},
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

// helper to call into PrepareForSigning()
func (round *round1) prepare() error {
	i := round.PartyID().Index

	privXi := round.key.PrivXi
	ks := round.key.Ks
	pubXjs := round.key.PubXj

	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
	}
	wi, bigWs := PrepareForSigning(round.Params().EC(), i, len(ks), privXi, ks, pubXjs)

	round.temp.wi = wi
	round.temp.bigWs = bigWs

	pubKey := bigWs[0]
	var err error
	for j, pubx := range bigWs {
		if j == 0 {
			continue
		}
		pubKey, err = pubKey.Add(pubx)
		if err != nil {
			common.Logger.Errorf("calc pubkey failed, party: %d", j)
			return round.WrapError(err)
		}
	}
	round.temp.pubW = pubKey

	return nil
}
