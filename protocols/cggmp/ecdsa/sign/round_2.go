package sign

import (
	"errors"
	"fmt"
	"math/big"
	sync "sync"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/crypto/affproof"
	"github.com/felicityin/mpc-tss/crypto/alice/mta"
	"github.com/felicityin/mpc-tss/crypto/logproof"
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

	contextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)

	// Verify received enc proof
	for j := range Ps {
		if j == i {
			continue
		}

		r1msg1 := round.temp.signRound1Message1s[j].Content().(*SignRound1Message1)
		round.temp.kCiphertexts[j] = r1msg1.UnmarshalK()
		round.temp.gammaCiphertexts[j] = r1msg1.UnmarshalGamma()
		common.Logger.Debugf("P[%d]: receive P[%d]'s kCiphertext and gammaCiphertext", i, j)

		r1msg2 := round.temp.signRound1Message2s[j].Content().(*SignRound1Message2)
		encProof, err := r1msg2.UnmarshalEncProof()
		if err != nil {
			common.Logger.Errorf("unmarshal enc proof failed, party: %d", j)
			return round.WrapError(err)
		}
		common.Logger.Debugf("P[%d]: receive P[%d]'s enc proof", i, j)

		if err := encProof.Verify(
			ProofParameter, contextI, round.temp.kCiphertexts[j],
			round.aux.PaillierPKs[j].N, round.aux.PedersenPKs[i],
		); err != nil {
			common.Logger.Errorf("verify enc proof failed, party: %d", j)
			return round.WrapError(err)
		}
		common.Logger.Debugf("P[%d]: verify P[%d]'s enc proof ok", i, j)
	}

	// Compute Gammai = gammai * G
	common.Logger.Debugf("P[%d]: calc Gammai", i)
	round.temp.Gamma = crypto.ScalarBaseMult(round.EC(), round.temp.gamma)

	var Ds = make([][]byte, len(round.Parties().IDs()))
	var Fs = make([]*big.Int, len(round.Parties().IDs()))
	var psiProofs = make([]*affproof.PaillierAffAndGroupRangeMessage, len(round.Parties().IDs()))
	var Dhats = make([][]byte, len(round.Parties().IDs()))
	var Fhats = make([]*big.Int, len(round.Parties().IDs()))
	var psiHatProofs = make([]*affproof.PaillierAffAndGroupRangeMessage, len(round.Parties().IDs()))

	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*2)
	wg := sync.WaitGroup{}
	wg.Add((len(round.Parties().IDs()) - 1) * 2)

	// Generates proofs for Pj
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			round.ok[j] = true
			continue
		}

		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			// aff-g proof: M(prove, Πaff-g, (sid, i), (Iε, Jε, Dj,i, Kj, Fj,i, Gi); (gammai, βi,j, si,j, ri,j))
			negBeta, countDelta, r, s, D, F, psiProof, err := mta.MtaWithProofAff_g(
				round.Rand(), contextI, round.aux.PedersenPKs[j], round.aux.PaillierPKs[i],
				round.temp.kCiphertexts[j], round.temp.gamma, round.temp.Gamma,
			)
			Ds[j], Fs[j], psiProofs[j], round.temp.beta[j], _, _, _ = D, F, psiProof, negBeta, countDelta, r, s
			if err != nil {
				common.Logger.Errorf("create aff-g proof 1 failed: %s", err.Error())
				errChs <- round.WrapError(fmt.Errorf("create aff-g proof 1 failed: %s", err.Error()))
			}
		}(j, Pj)

		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			// aff-g proof: M(prove, Πaff-g, (sid, i), (Iε, Jε, Dˆj,i, Kj, Fˆj,i, Xi); (xi, βˆi,j, sˆi,j, rˆi,j))
			negBetaHat, countSigma, rhat, shat, Dhat, Fhat, psiHatProof, err := mta.MtaWithProofAff_g(
				round.Rand(), contextI, round.aux.PedersenPKs[j], round.aux.PaillierPKs[i],
				round.temp.kCiphertexts[j], round.key.PrivXi, round.key.PubXj[i],
			)
			Dhats[j], Fhats[j], psiHatProofs[j], round.temp.betaHat[j], _, _, _ = Dhat, Fhat, psiHatProof, negBetaHat, countSigma, rhat, shat
			if err != nil {
				common.Logger.Errorf("create aff-g proof 2 failed: %s", err.Error())
				errChs <- round.WrapError(fmt.Errorf("create aff-g proof 2 failed: %s", err.Error()))
			}
		}(j, Pj)
	}

	// Consume error channels; wait for goroutines
	wg.Wait()
	close(errChs)
	culprits := make([]*tss.PartyID, 0, len(round.Parties().IDs()))
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("failed to calculate affg proof"), culprits...)
	}

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		// log proof for the secret gamma, mu: M(prove, Πlog, (sid, i), (Iε, Gi, Γi, g); (γi, νi))
		logProof, err := logproof.NewKnowExponentAndPaillierEncryption(
			ProofParameter, contextI, round.temp.gamma, round.temp.mu, round.temp.gammaCiphertexts[i],
			round.aux.PaillierPKs[i].N, round.aux.PedersenPKs[j], round.temp.Gamma, nil,
		)
		if err != nil {
			common.Logger.Errorf("create log proof failed: %s", err.Error())
			return round.WrapError(fmt.Errorf("create log proof failed: %s", err.Error()))
		}

		common.Logger.Debugf("P[%d]: send proofs to P[%d]", i, j)
		r2msg, err := NewSignRound2Message(
			Pj, round.PartyID(), round.temp.Gamma, Ds[j], Fs[j], Dhats[j], Fhats[j], psiProofs[j], psiHatProofs[j], logProof,
		)
		if err != nil {
			return round.WrapError(err, Pj)
		}
		round.out <- r2msg
	}
	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound2Message); ok {
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
