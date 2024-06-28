package keygen

import (
	"bytes"
	"errors"
	"math/big"
	"strconv"

	"mpc_tss/common"
	"mpc_tss/crypto/alice/utils"
	"mpc_tss/crypto/schnorr"
	"mpc_tss/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round 3 already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("party: %d, round_3 start", i)

	for j, msg := range round.temp.kgRound2Messages {
		if j == i {
			continue
		}

		r2Msg := msg.Content().(*KGRound2Message)

		var err error
		round.temp.payload[j], err = r2Msg.UnmarshalPayload(round.EC())
		if err != nil {
			return round.WrapError(err)
		}
		round.save.PubXj[j], err = r2Msg.UnmarshalPubXj(round.EC())
		if err != nil {
			return round.WrapError(err)
		}

		if !bytes.Equal(round.temp.payload[j].ssid, round.temp.ssid) {
			common.Logger.Errorf("payload.ssid != round.temp.ssid, party: %d", j)
			return round.WrapError(errors.New("ssid verify failed"))
		}

		common.Logger.Debugf("party: %d, round_3, calc V", i)
		v := common.SHA512_256(
			round.temp.ssid,
			[]byte(strconv.Itoa(j)),
			round.temp.payload[j].srid,
			round.save.PubXj[j].X().Bytes(),
			round.save.PubXj[j].Y().Bytes(),
			round.temp.payload[j].commitedA.X().Bytes(),
			round.temp.payload[j].commitedA.Y().Bytes(),
			round.temp.payload[j].u,
		)

		// Verify commited V_i
		if !bytes.Equal(v, round.temp.V[j]) {
			common.Logger.Errorf("hash != V, party: %d", j)
			return round.WrapError(errors.New("commited v_i verify failed"))
		}

		// Set srid as xor of all party's srid_i
		common.Logger.Debugf("party: %d, round_3, calc srid", i)
		round.temp.srid = utils.Xor(round.temp.srid, round.temp.payload[j].srid)
	}

	common.Logger.Debugf("party: %d, round_3, calc challenge", i)
	challenge := common.RejectionSample(
		round.EC().Params().N,
		common.SHA512_256i_TAGGED(
			append(round.temp.ssid, round.temp.srid...),
			big.NewInt(int64(i)),
			round.save.PubXj[i].X(),
			round.save.PubXj[i].Y(),
			round.temp.commitedA.X(),
			round.temp.commitedA.Y(),
		),
	)

	// Generate schnorr proof
	common.Logger.Debugf("party: %d, round_3, calc schnorr proof", i)
	schProof := schnorr.Prove(round.EC().Params().N, round.temp.tau, challenge, round.save.PrivXi)

	// BROADCAST proofs
	common.Logger.Infof("party: %d, round_3 broadcast", i)
	{
		msg := NewKGRound3Message(round.PartyID(), schProof.Proof.Bytes())
		round.temp.kgRound3Messages[i] = msg
		round.out <- msg
	}
	return nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.kgRound3Messages {
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

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
