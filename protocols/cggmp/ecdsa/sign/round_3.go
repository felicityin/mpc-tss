package sign

import (
	"fmt"
	"math/big"
	sync "sync"

	"github.com/pkg/errors"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto/logproof"
	"github.com/felicityin/mpc-tss/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 3
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("[sign] party: %d, round_3 start", i)

	// Γ = sum_j Γj
	sumGamma := round.temp.Gamma

	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*3)
	wg := sync.WaitGroup{}
	wg.Add((len(round.Parties().IDs()) - 1) * 2)

	// verify received proofs
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		contextJ := append(round.temp.ssid, big.NewInt(int64(j)).Bytes()...)
		r2msg := round.temp.signRound2Messages[j].Content().(*SignRound2Message)

		Gamma, err := r2msg.UnmarshalGamma()
		if err != nil {
			return round.WrapError(err, Pj)
		}
		sumGamma, err = sumGamma.Add(Gamma)
		if err != nil {
			return round.WrapError(err, Pj)
		}

		psiProof, err := r2msg.UnmarshalAffgProof()
		if err != nil {
			common.Logger.Errorf("[j: %d] failed to unmarshal affg proof: %s", j, err.Error())
			return round.WrapError(fmt.Errorf("[j: %d] failed to unmarshal affg proof: %s", j, err.Error()))
		}
		common.Logger.Debugf("P[%d]: receive P[%d]'s affg proof", i, j)

		psiHatProof, err := r2msg.UnmarshalAffgHatProof()
		if err != nil {
			common.Logger.Errorf("[j: %d] failed to unmarshal affg_hat proof: %s", j, err.Error())
			return round.WrapError(fmt.Errorf("[j: %d] failed to unmarshal affg_hat proof: %s", j, err.Error()))
		}
		common.Logger.Debugf("P[%d]: receive P[%d]'s affg_hat proof", i, j)

		logProof, err := r2msg.UnmarshalLogProof()
		if err != nil {
			common.Logger.Errorf("[j: %d] failed to unmarshal log proof: %s", j, err.Error())
			return round.WrapError(fmt.Errorf("failed to unmarshal log proof: %s", err.Error()), Pj)
		}
		common.Logger.Debugf("P[%d]: receive P[%d]'s log proof", i, j)

		go func(j int) {
			defer wg.Done()

			if err = psiProof.Verify(
				ProofParameter, contextJ, round.aux.PaillierPKs[i].N, round.aux.PedersenPKs[j].N, round.temp.kCiphertexts[i],
				new(big.Int).SetBytes(r2msg.GetD()), new(big.Int).SetBytes(r2msg.GetF()), round.aux.PedersenPKs[i], Gamma,
			); err != nil {
				common.Logger.Errorf("[j: %d] failed to verify affg proof: %s", j, err)
				errChs <- round.WrapError(fmt.Errorf("[j: %d] failed to verify affg proof: %s", j, err.Error()))
			}
		}(j)

		go func(j int) {
			defer wg.Done()

			if err = psiHatProof.Verify(
				ProofParameter, contextJ, round.aux.PaillierPKs[i].N, round.aux.PedersenPKs[j].N, round.temp.kCiphertexts[i],
				new(big.Int).SetBytes(r2msg.GetDHat()), new(big.Int).SetBytes(r2msg.GetFHat()), round.aux.PedersenPKs[i], round.key.PubXj[j],
			); err != nil {
				common.Logger.Errorf("[j: %d] failed to verify affg_hat proof: %s", j, err)
				errChs <- round.WrapError(fmt.Errorf("failed to verify affg_hat proof: %s", err.Error()), Pj)
			}

			if err := logProof.Verify(
				ProofParameter, contextJ, round.temp.gammaCiphertexts[j], round.aux.PaillierPKs[j].N,
				round.aux.PedersenPKs[i], Gamma, nil,
			); err != nil {
				common.Logger.Errorf("verify log proof failed: %s, party: %d", err, j)
				errChs <- round.WrapError(fmt.Errorf("verify log proof failed: %s", err), Pj)
			}
			common.Logger.Debugf("P[%d]: verify P[%d]'s log proof ok", i, j)
		}(j)
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

	round.temp.sumGamma = sumGamma

	// ∆i = Γ^ki
	round.temp.Delta = sumGamma.ScalarMult(round.temp.k)
	// δi = γi * ki + sum(αi,j + βi,j) mod q
	delta := new(big.Int).Mul(round.temp.gamma, round.temp.k)
	// χi = xi * ki + sum(α̂ i,j + β̂ i,j) mod q
	chi := new(big.Int).Mul(round.key.PrivXi, round.temp.k)

	// calculate δi, χi
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}

		r2msg := round.temp.signRound2Messages[j].Content().(*SignRound2Message)

		alpha, err := round.aux.PaillierSK.Decrypt(new(big.Int).SetBytes(r2msg.GetD()))
		if err != nil {
			common.Logger.Errorf("[j: %d] failed to decrypt alpha: %s", j, err)
			return round.WrapError(fmt.Errorf("[j: %d] failed to decrypt alpha: %s", j, err))
		}

		alphaHat, err := round.aux.PaillierSK.Decrypt(new(big.Int).SetBytes(r2msg.GetDHat()))
		if err != nil {
			common.Logger.Errorf("[j: %d] failed to decrypt alpha_hat: %s", j, err)
			return round.WrapError(fmt.Errorf("[j: %d] failed to decrypt alpha: %s", j, err))
		}

		delta.Add(delta, alpha)
		delta.Add(delta, round.temp.beta[j])
		delta.Mod(delta, round.EC().Params().N)

		chi.Add(chi, alphaHat)
		chi.Add(chi, round.temp.betaHat[j])
		chi.Mod(chi, round.EC().Params().N)
	}

	round.temp.delta = delta
	round.temp.chi = chi

	// P2P send log proof to Pj
	contextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			round.ok[j] = true
			continue
		}
		// log proof: M(prove, Πlog, (ssid, i), (Iε, Ki, ∆i, Γ); (ki, ρi))
		logProof, err := logproof.NewKnowExponentAndPaillierEncryption(
			ProofParameter, contextI, round.temp.k, round.temp.rho, round.temp.kCiphertexts[i],
			round.aux.PaillierPKs[i].N, round.aux.PedersenPKs[j], round.temp.Delta, sumGamma,
		)
		if err != nil {
			common.Logger.Errorf("[j: %d] create log proof failed: %s", j, err.Error())
			return round.WrapError(fmt.Errorf("[j: %d] create log proof failed: %s", j, err.Error()))
		}

		common.Logger.Debugf("P[%d]: send log proof to P[%d]", i, j)
		r3msg, err := NewSignRound3Message(Pj, round.PartyID(), delta, round.temp.Delta, logProof)
		if err != nil {
			return round.WrapError(err, Pj)
		}
		round.out <- r3msg
	}

	return nil
}

func (round *round3) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound3Messages {
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

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound3Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
