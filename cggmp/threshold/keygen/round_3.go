package keygen

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/crypto/alice/utils"
	"github.com/felicityin/mpc-tss/crypto/commitments"
	"github.com/felicityin/mpc-tss/crypto/schnorr"
	"github.com/felicityin/mpc-tss/crypto/vss"
	"github.com/felicityin/mpc-tss/tss"
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

	pjVss := make([]vss.Vs, round.PartyCount())
	xi := new(big.Int).Set(round.temp.shares[i].Share)

	for j, msg := range round.temp.kgRound2Message1s {
		if j == i {
			continue
		}

		r2msg1 := msg.Content().(*TKgRound2Message1)

		commitmentA, err := r2msg1.UnmarshalSchCommitment()
		if err != nil {
			return round.WrapError(fmt.Errorf("[j: %d] unmalshal commitment failed", j))
		}
		round.temp.commitedA[j] = commitmentA

		KGDj := r2msg1.UnmarshalDeCommitment()
		cmtDeCmt := commitments.HashCommitDecommit{C: round.temp.KGCs[j], D: KGDj}
		ok, flatPolyGs := cmtDeCmt.DeCommit()
		if !ok || flatPolyGs == nil {
			return round.WrapError(fmt.Errorf("[j: %d] de-commitment verify failed", j))
		}

		PjVs, err := crypto.UnFlattenECPoints(round.Params().EC(), flatPolyGs)
		if err != nil {
			return round.WrapError(fmt.Errorf("[j: %d] UnFlattenECPoints err: %s", j, err.Error()))
		}
		pjVss[j] = PjVs

		if !bytes.Equal(r2msg1.GetSsid(), round.temp.ssid) {
			common.Logger.Errorf("[%d] payload.ssid != round.temp.ssid", j)
			return round.WrapError(fmt.Errorf("[%d] ssid verify failed", j))
		}

		// Verify commited V_j
		common.Logger.Debugf("[j: %d]round_3, calc V", j)
		Vj := common.SHA512_256(
			r2msg1.GetSsid(),
			[]byte(strconv.Itoa(round.PartyCount())),
			[]byte(strconv.Itoa(j)),
			[]byte(strconv.Itoa(round.Threshold())),
			r2msg1.GetSrid(),
			cmtDeCmt.C.Bytes(),
			commitmentA.X().Bytes(),
			commitmentA.Y().Bytes(),
			r2msg1.GetU(),
			r2msg1.GetChainCode(),
		)
		if !bytes.Equal(Vj, round.temp.V[j]) {
			common.Logger.Errorf("[j: %d] hash != V", j)
			return round.WrapError(fmt.Errorf("[%d] commited v_i verify failed", j))
		}

		r2msg2 := round.temp.kgRound2Message2s[j].Content().(*TKgRound2Message2)
		share := r2msg2.UnmarshalShare()
		PjShare := vss.Share{
			Threshold: round.Threshold(),
			ID:        round.PartyID().KeyInt(),
			Share:     share,
		}
		if ok = PjShare.Verify(round.Params().EC(), round.Threshold(), PjVs); !ok {
			return round.WrapError(fmt.Errorf("[j: %d] vss verify failed", j))
		}

		// Calculate private key
		xi = xi.Add(xi, share)

		// Set srid as xor of all party's srid_j
		common.Logger.Debugf("[j: %d] round_3, calc srid", j)
		round.temp.srid = utils.Xor(round.temp.srid, r2msg1.GetSrid())
		round.temp.chainCode = utils.Xor(round.temp.chainCode, r2msg1.GetChainCode())
	}

	round.save.PrivXi = xi.Mod(xi, round.Params().EC().Params().N)
	round.save.ChainCode = new(big.Int).SetBytes(round.temp.chainCode)

	// Ours
	Vc := make(vss.Vs, round.Threshold()+1)
	for c := range Vc {
		Vc[c] = round.temp.vs[c]
	}

	// Compute F(x)
	{
		var err error
		for j := 0; j < round.PartyCount(); j++ {
			if j == i {
				continue
			}
			PjVs := pjVss[j]
			for c := 0; c <= round.Threshold(); c++ {
				Vc[c], err = Vc[c].Add(PjVs[c])
				if err != nil {
					common.Logger.Errorf("calc F(x) err: %s", err.Error())
					return round.WrapError(fmt.Errorf("calc F(x) err: %s", err.Error()))
				}
			}
		}
	}

	// Compute Xj for each Pj
	{
		var err error
		modQ := common.ModInt(round.Params().EC().Params().N)
		bigXj := round.save.PubXj
		for j := 0; j < round.PartyCount(); j++ {
			Pj := round.Parties().IDs()[j]
			kj := Pj.KeyInt()
			BigXj := Vc[0]
			z := new(big.Int).SetInt64(int64(1))
			for c := 1; c <= round.Threshold(); c++ {
				z = modQ.Mul(z, kj)
				BigXj, err = BigXj.Add(Vc[c].ScalarMult(z))
				if err != nil {
					return round.WrapError(errors.New("adding Vc[c].ScalarMult(z) to BigXj resulted in a point not on the curve"))
				}
			}
			bigXj[j] = BigXj
		}
		round.save.PubXj = bigXj
	}

	// Compute and save the public key
	pubKey, err := crypto.NewECPoint(round.Params().EC(), Vc[0].X(), Vc[0].Y())
	if err != nil {
		return round.WrapError(fmt.Errorf("public key is not on the curve: %s", err.Error()))
	}
	round.save.Pubkey = pubKey

	common.Logger.Debugf("party: %d, round_3, calc challenge", i)
	challenge := common.RejectionSample(
		round.EC().Params().N,
		common.SHA512_256i_TAGGED(
			append(round.temp.ssid, round.temp.srid...),
			big.NewInt(int64(i)),
			round.save.PubXj[i].X(),
			round.save.PubXj[i].Y(),
			round.temp.commitedA[i].X(),
			round.temp.commitedA[i].Y(),
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
	if _, ok := msg.Content().(*TKgRound3Message); ok {
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
