package auxiliary

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/crypto/prmproof"
	"github.com/felicityin/mpc-tss/tss"
)

var ProofParameter = crypto.NewProofConfig(tss.S256().Params().N)

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

	if round.save.PaillierSK == nil {
		round.save.PaillierSK, err = GeneratePaillier(round.Rand())
		if err != nil {
			return round.WrapError(errors.New("paillier sk generation failed"), Pi)
		}
	}
	round.save.PaillierPKs[i] = &round.save.PaillierSK.PublicKey

	// Set pedersen parameter from paillierKey: Sample r in Z_N^ast, lambda = Z_phi(N), t = r^2 and s = t^lambda mod N
	pedersen, err := round.save.PaillierSK.NewPedersenParameterByPaillier()
	if err != nil {
		common.Logger.Errorf("generate ring-pedersen keys failed")
		return round.WrapError(errors.New("generate ring-pedersen keys failed"), Pi)
	}
	round.save.PedersenPKs[i] = pedersen.PedersenOpenParameter

	// Generate prm proof
	contextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)
	prmProof, err := prmproof.NewRingPederssenParameterMessage(
		contextI,
		pedersen.GetEulerValue(),
		pedersen.PedersenOpenParameter.GetN(),
		pedersen.PedersenOpenParameter.GetS(),
		pedersen.PedersenOpenParameter.GetT(),
		pedersen.Getlambda(),
		prmproof.MINIMALCHALLENGE,
	)
	if err != nil {
		return round.WrapError(fmt.Errorf("party: %d, generate prm proof error: %s", i, err.Error()))
	}
	round.temp.prmProof = prmProof

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
