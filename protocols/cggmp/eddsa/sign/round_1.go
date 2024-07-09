package sign

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/crypto/encproof"
	"github.com/felicityin/mpc-tss/protocols"
	"github.com/felicityin/mpc-tss/protocols/cggmp/auxiliary"
	"github.com/felicityin/mpc-tss/protocols/cggmp/keygen"
	"github.com/felicityin/mpc-tss/tss"

	edwards "github.com/decred/dcrd/dcrec/edwards/v2"
	"google.golang.org/protobuf/proto"
)

var ProofParameter = crypto.NewProofConfig(edwards.Edwards().N)

// round 1 represents round 1 of the signing part of the EDDSA TSS spec
func newRound1(
	isThreshold bool,
	params *tss.Parameters,
	key *keygen.LocalPartySaveData,
	aux *auxiliary.LocalPartySaveData,
	data *common.SignatureData,
	temp *localTempData,
	out chan<- tss.Message,
	end chan<- *common.SignatureData,
) tss.Round {
	return &round1{
		&base{params, isThreshold, key, aux, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1},
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

	// k in F_q
	round.temp.k = common.GetRandomPositiveInt(round.Rand(), round.Params().EC().Params().N)
	common.Logger.Debugf("P[%d]: calc ki", i)

	// Ki = enc(k, ρ)
	kCiphertext, rho, err := round.aux.PaillierPKs[i].EncryptAndReturnRandomness(
		round.Rand(),
		round.temp.k,
	)
	if err != nil {
		common.Logger.Errorf("P[%d]: create enc proof failed: %s", i, err)
		return round.WrapError(err)
	}
	round.temp.rho = rho
	round.temp.kCiphertexts[i] = kCiphertext
	common.Logger.Debugf("P[%d]: calc kCiphertext", i)

	// broadcast Ki
	common.Logger.Debugf("P[%d]: broadcast Ki", i)
	r1msg1 := NewSignRound1Message1(round.PartyID(), kCiphertext)
	round.temp.signRound1Message1s[i] = r1msg1
	round.out <- r1msg1

	contextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)

	// p2p send enc proof to Pj
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			round.ok[j] = true
			continue
		}
		// M(prove, Πenc, (sid,i), (Iε,Ki); (ki,rhoi))
		encProof, err := encproof.NewEncryptRangeMessage(ProofParameter, contextI, kCiphertext,
			round.aux.PaillierPKs[i].N, round.temp.k, round.temp.rho, round.aux.PedersenPKs[j],
		)
		if err != nil {
			common.Logger.Errorf("create enc proof failed: %s, party: %d", err, j)
			return round.WrapError(errors.New("create enc proof failed"))
		}
		common.Logger.Debugf("P[%d]: calc enc proof", i)

		encProofBytes, err := proto.Marshal(encProof)
		if err != nil {
			common.Logger.Errorf("marshal enc proof failed: %s, party: %d", err, j)
			return round.WrapError(errors.New("marshal enc proof failed"))
		}

		common.Logger.Debugf("P[%d]: p2p send enc proof", i)
		r1msg2 := NewSignRound1Message2(Pj, round.PartyID(), encProofBytes)
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

// helper to call into PrepareForSigning()
func (round *round1) prepare() error {
	i := round.PartyID().Index

	if !round.isThreshold {
		round.temp.wi = round.key.PrivXi
		round.temp.bigWs = round.key.PubXj
		round.temp.pubW = round.key.Pubkey
	} else {
		privXi := round.key.PrivXi
		ks := round.key.Ks
		pubXjs := round.key.PubXj

		if round.Threshold()+1 > len(ks) {
			return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
		}

		wi, bigWs, pubKey, err := protocols.PrepareForSigning(round.Params().EC(), i, len(ks), privXi, ks, pubXjs)
		if err != nil {
			return err
		}

		round.temp.wi = wi
		round.temp.bigWs = bigWs
		round.temp.pubW = pubKey
	}
	return nil
}
