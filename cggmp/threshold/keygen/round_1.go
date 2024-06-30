package keygen

import (
	"errors"
	"math/big"
	"strconv"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	cmts "github.com/felicityin/mpc-tss/crypto/commitments"
	"github.com/felicityin/mpc-tss/crypto/vss"
	"github.com/felicityin/mpc-tss/tss"
)

var zero = big.NewInt(0)

// round 1 represents round 1 of the keygen part of the TSS spec
func newRound1(
	params *tss.Parameters,
	save *LocalPartySaveData,
	temp *localTempData,
	out chan<- tss.Message,
	end chan<- *LocalPartySaveData,
) tss.Round {
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

	// Calculate "partial" key share s0
	s0 := common.GetRandomPositiveInt(round.PartialKeyRand(), round.EC().Params().N)
	round.temp.s0 = s0

	// Compute the vss shares
	ids := round.Parties().IDs().Keys()
	vs, shares, err := vss.Create(round.EC(), round.Threshold(), s0, ids, round.Rand())
	if err != nil {
		return round.WrapError(err, Pi)
	}
	round.save.Ks = ids
	round.temp.vs = vs
	round.temp.shares = shares

	// Security: the original u_i may be discarded
	s0 = zero // clears the secret data from memory
	_ = s0    // silences a linter warning

	// Make commitment -> (C, D)
	pGFlat, err := crypto.FlattenECPoints(vs)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	polyCmt := cmts.NewHashCommitment(round.Rand(), pGFlat...)
	round.temp.deCommitPolyG = polyCmt.D
	round.temp.KGCs[i] = polyCmt.C

	// Make zk-schnorr commitment
	round.temp.tau = common.GetRandomPositiveInt(round.PartialKeyRand(), round.Params().EC().Params().N)
	round.temp.commitedA[i] = crypto.ScalarBaseMult(round.EC(), round.temp.tau)

	round.save.ShareID = ids[i]
	round.temp.srid, _ = common.GetRandomBytes(round.Rand(), 32)
	round.temp.ssidNonce = new(big.Int).SetUint64(0)
	ssid, err := round.getSSID()
	if err != nil {
		return round.WrapError(errors.New("failed to generate ssid"))
	}
	round.temp.ssid = ssid

	round.temp.u, _ = common.GetRandomBytes(round.Rand(), 32)
	round.temp.chainCode, _ = common.GetRandomBytes(round.Rand(), 32)

	// Compute V_i
	Vi := common.SHA512_256(
		ssid,
		[]byte(strconv.Itoa(round.PartyCount())),
		[]byte(strconv.Itoa(i)),
		[]byte(strconv.Itoa(round.Threshold())),
		round.temp.srid,
		polyCmt.C.Bytes(),
		round.temp.commitedA[i].X().Bytes(),
		round.temp.commitedA[i].Y().Bytes(),
		round.temp.u,
		round.temp.chainCode,
	)

	common.Logger.Infof("party: %d, round_1 broadcast", i)

	// BROADCAST commitments
	{
		msg := NewKGRound1Message(round.PartyID(), Vi, polyCmt.C)
		round.temp.kgRound1Messages[i] = msg
		round.out <- msg
	}
	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*TKgRound1Message); ok {
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
