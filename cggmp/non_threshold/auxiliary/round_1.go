package auxiliary

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"mpc_tss/common"
	paillierzkproof "mpc_tss/crypto/alice/zkproof/paillier"
	"mpc_tss/crypto/modproof"
	"mpc_tss/crypto/paillier"
	"mpc_tss/tss"
)

// round 1 represents round 1 of the keygen part of the EDDSA TSS spec
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

	ids := round.Parties().IDs().Keys()
	round.save.Ks = ids
	round.save.ShareID = ids[i]

	round.temp.ssidNonce = new(big.Int).SetUint64(0)
	ssid, err := round.getSSID()
	if err != nil {
		return round.WrapError(err)
	}
	round.temp.ssid = ssid

	var paillierSk *paillier.PrivateKey
	{
		ctx, cancel := context.WithTimeout(context.Background(), round.SafePrimeGenTimeout())
		defer cancel()
		paillierSk, err = GeneratePreParamsWithContextAndRandom(ctx, round.Rand(), round.Concurrency())
		if err != nil {
			return round.WrapError(errors.New("paillier sk generation failed"), Pi)
		}
	}
	round.save.PaillierSK = paillierSk
	round.save.PaillierPKs[i] = &paillierSk.PublicKey

	// Set pedersen parameter from paillierKey: Sample r in Z_N^ast, lambda = Z_phi(N), t = r^2 and s = t^lambda mod N
	pedersen, err := paillierSk.NewPedersenParameterByPaillier()
	if err != nil {
		common.Logger.Errorf("generate ring-pedersen keys failed")
		return round.WrapError(errors.New("generate ring-pedersen keys failed"), Pi)
	}
	// round.save.PedersenSK = &pailliera.PedPrivKey{
	// 	LambdaN: pedersen.Getlambda(),
	// 	Euler:   pedersen.GetEulerValue(),
	// }
	round.save.PedersenPKs[i] = pedersen.PedersenOpenParameter

	// Generate prm proof
	contextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)
	prmProof, err := paillierzkproof.NewRingPederssenParameterMessage(
		contextI,
		pedersen.GetEulerValue(),
		pedersen.PedersenOpenParameter.GetN(),
		pedersen.PedersenOpenParameter.GetS(),
		pedersen.PedersenOpenParameter.GetT(),
		pedersen.Getlambda(),
		paillierzkproof.MINIMALCHALLENGE,
	)
	if err != nil {
		return round.WrapError(fmt.Errorf("party: %d, generate prm proof error: %s", i, err.Error()))
	}
	round.temp.prmProof = prmProof

	// Generate mod proof
	modProof, err := modproof.NewProof(contextI, round.save.PaillierPKs[i].N,
		round.save.PaillierSK.P, round.save.PaillierSK.Q, round.Rand())
	if err != nil {
		return round.WrapError(fmt.Errorf("party %d, calc mod proof failed: %s", i, err.Error()))
	}
	round.temp.modProof = modProof

	round.temp.u, _ = common.GetRandomBytes(round.Rand(), 32)
	round.temp.rho, _ = common.GetRandomBytes(round.Rand(), 32)
	round.temp.srid, _ = common.GetRandomBytes(round.Rand(), 32)

	// Compute V_i
	hash := common.SHA512_256(
		ssid,
		[]byte(strconv.Itoa(i)),
		round.temp.srid,
		round.save.PaillierPKs[i].N.Bytes(),
		round.save.PedersenPKs[i].S.Bytes(),
		round.save.PedersenPKs[i].T.Bytes(),
		prmProof.Salt,
		modProof.A.Bytes(),
		modProof.B.Bytes(),
		modProof.W.Bytes(),
		round.temp.rho,
		round.temp.u,
	)

	common.Logger.Infof("party: %d, round_1 broadcast", i)

	// BROADCAST commitments
	{
		msg := NewAuxRound1Message(round.PartyID(), hash)
		round.temp.auxRound1Messages[i] = msg
		round.out <- msg
	}
	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*AuxRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.auxRound1Messages {
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
