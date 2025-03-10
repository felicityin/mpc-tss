package presign

import (
	"errors"
	"math/big"

	"google.golang.org/protobuf/proto"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/crypto/logproof"
	"github.com/felicityin/mpc-tss/protocols/cggmp/eddsa/sign"
	"github.com/felicityin/mpc-tss/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	Ps := round.Parties().IDs()
	common.Logger.Infof("[sign] party: %d, round_2 start", i)

	// Verify received enc proof
	for j := range Ps {
		if j == i {
			continue
		}

		r1msg1 := round.temp.signRound1Message1s[j].Content().(*sign.SignRound1Message1)
		round.temp.kCiphertexts[j] = r1msg1.UnmarshalK()
		common.Logger.Debugf("P[%d]: receive P[%d]'s kCiphertext", i, j)

		r1msg2 := round.temp.signRound1Message2s[j].Content().(*sign.SignRound1Message2)
		encProof, err := r1msg2.UnmarshalEncProof()
		if err != nil {
			common.Logger.Errorf("unmarshal enc proof failed, party: %d", j)
			return round.WrapError(err)
		}
		common.Logger.Debugf("P[%d]: receive P[%d]'s enc proof", i, j)

		contextJ := append(round.temp.ssid, big.NewInt(int64(j)).Bytes()...)

		if err := encProof.Verify(
			ProofParameter, contextJ, round.temp.kCiphertexts[j],
			round.aux.PaillierPKs[j].N, round.aux.PedersenPKs[i],
		); err != nil {
			common.Logger.Errorf("verify enc proof failed, party: %d", j)
			return round.WrapError(err)
		}
		common.Logger.Debugf("P[%d]: verify P[%d]'s enc proof ok", i, j)
	}

	// Compute Ri = ki * G
	common.Logger.Debugf("P[%d]: calc Ri", i)
	Ri := crypto.ScalarBaseMult(round.EC(), round.save.K)

	contextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)

	// p2p send log proof to Pj
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			round.ok[j] = true
			continue
		}
		// logProof for the secret k, rho: M(prove, Πlog, (sid,i), (Iε,Ki,Ri,g); (ki,rhoi))
		logProof, err := logproof.NewKnowExponentAndPaillierEncryption(
			ProofParameter, contextI, round.save.K, round.temp.rho, round.temp.kCiphertexts[i],
			round.aux.PaillierPKs[i].N, round.aux.PedersenPKs[j], Ri, nil,
		)
		if err != nil {
			common.Logger.Errorf("create log proof failed")
			return round.WrapError(err)
		}
		common.Logger.Debugf("P[%d]: calc log proof for P[%d]", i, j)

		logProofBytes, err := proto.Marshal(logProof)
		if err != nil {
			common.Logger.Errorf("marshal log proof failed: %s, party: %d", err, j)
			return round.WrapError(errors.New("marshal log proof failed"))
		}

		common.Logger.Debugf("P[%d]: send log proof to P[%d]", i, j)
		r2msg := sign.NewSignRound2Message(Pj, round.PartyID(), Ri, logProofBytes)
		round.out <- r2msg
	}

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*sign.SignRound2Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound2Messages {
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
