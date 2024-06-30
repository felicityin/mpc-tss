package sign

import (
	"errors"
	"math/big"

	"mpc_tss/cggmp/non_threshold/auxiliary"
	"mpc_tss/cggmp/non_threshold/keygen"
	"mpc_tss/common"
	"mpc_tss/crypto"
	"mpc_tss/crypto/encproof"
	"mpc_tss/tss"
)

var ProofParameter = crypto.NewProofConfig(tss.S256().Params().N)

// round 1 represents round 1 of the signing part of the EDDSA TSS spec
func newRound1(
	params *tss.Parameters,
	key *keygen.LocalPartySaveData,
	aux *auxiliary.LocalPartySaveData,
	data *common.SignatureData,
	temp *localTempData,
	out chan<- tss.Message,
	end chan<- *common.SignatureData,
) tss.Round {
	return &round1{
		&base{params, key, aux, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1},
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

	// k, gamma in F_q
	round.temp.k = common.GetRandomPositiveInt(round.Rand(), round.EC().Params().N)
	round.temp.gamma = common.GetRandomPositiveInt(round.Rand(), round.EC().Params().N)
	common.Logger.Debugf("P[%d]: calc ki, gammai", i)

	// Ki = enc(k, ρ), Gammai = enc(gamma, mu)
	round.temp.kCiphertexts[i], round.temp.rho, err = round.aux.PaillierPKs[i].EncryptAndReturnRandomness(
		round.Rand(),
		round.temp.k,
	)
	if err != nil {
		common.Logger.Errorf("P[%d]: create enc proof failed: %s", i, err)
		return round.WrapError(err)
	}
	round.temp.gammaCiphertexts[i], round.temp.mu, err = round.aux.PaillierPKs[i].EncryptAndReturnRandomness(
		round.Rand(),
		round.temp.gamma,
	)
	if err != nil {
		common.Logger.Errorf("P[%d]: create enc proof failed: %s", i, err)
		return round.WrapError(err)
	}
	common.Logger.Debugf("P[%d]: calc kCiphertext, gammaCiphertext done", i)

	// broadcast Ki, Gammai
	common.Logger.Debugf("P[%d]: broadcast Ki", i)
	r1msg1 := NewSignRound1Message1(round.PartyID(), round.temp.kCiphertexts[i], round.temp.gammaCiphertexts[i])
	round.temp.signRound1Message1s[i] = r1msg1
	round.out <- r1msg1

	// p2p send enc proof to Pj
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			round.ok[j] = true
			continue
		}
		contextJ := append(round.temp.ssid, big.NewInt(int64(j)).Bytes()...)

		// M(prove, Πenc, (sid,i), (Iε,Ki); (ki,rhoi))
		encProof, err := encproof.NewEncryptRangeMessage(
			ProofParameter, contextJ, round.temp.kCiphertexts[i],
			round.aux.PaillierPKs[i].N, round.temp.k, round.temp.rho, round.aux.PedersenPKs[j],
		)
		if err != nil {
			common.Logger.Errorf("create enc proof failed: %s, party: %d", err, j)
			return round.WrapError(errors.New("create enc proof failed"))
		}
		common.Logger.Debugf("P[%d]: calc enc proof", i)

		common.Logger.Debugf("P[%d]: p2p send enc proof", i)
		r1msg2, err := NewSignRound1Message2(Pj, round.PartyID(), encProof)
		if err != nil {
			round.WrapError(err, Pj)
		}
		round.out <- r1msg2
	}

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound1Message1s {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		msg2 := round.temp.signRound1Message2s[j]
		if msg2 == nil || !round.CanAccept(msg2) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message1); ok {
		return msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound1Message2); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
