package signing

import (
	"crypto/sha512"
	"fmt"
	"math/big"
	"strconv"

	"github.com/agl/ed25519/edwards25519"
	"github.com/pkg/errors"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/protocols"
	"github.com/felicityin/mpc-tss/protocols/cggmp/keygen"
	"github.com/felicityin/mpc-tss/protocols/frost/presign"
	"github.com/felicityin/mpc-tss/protocols/frost/sign"
	"github.com/felicityin/mpc-tss/tss"
)

// round 1 represents round 1 of the signing part of the EDDSA TSS spec
func newRound1(
	isThreshold bool,
	params *tss.Parameters,
	key *keygen.LocalPartySaveData,
	pre *presign.LocalPartySaveData,
	data *common.SignatureData,
	temp *localTempData,
	out chan<- tss.Message,
	end chan<- *common.SignatureData,
) tss.Round {
	return &round1{
		&base{params, isThreshold, key, pre, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1},
	}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("[sign] party: %d, round_2 start", i)

	round.temp.ssidNonce = new(big.Int).SetUint64(0)
	var err error
	round.temp.ssid, err = round.getSSID()
	if err != nil {
		return round.WrapError(err)
	}

	var B []byte

	for j := range round.Parties().IDs() {
		bs := common.SHA512_256(
			round.pre.DEs[j].D.X().Bytes(),
			round.pre.DEs[j].D.Y().Bytes(),
			round.pre.DEs[j].E.X().Bytes(),
			round.pre.DEs[j].E.Y().Bytes(),
		)

		B = append(B, round.temp.bigWs[j].X().Bytes()...)
		B = append(B, bs...)
	}

	rhoi := new(big.Int).SetBytes(
		common.SHA512_256([]byte(strconv.Itoa(i)), round.temp.m.Bytes(), common.SHA512_256(B)),
	)
	rhoi.Mod(rhoi, round.EC().Params().N)

	ki := new(big.Int).Mul(round.pre.E, rhoi)
	ki.Add(ki, round.pre.D)
	ki.Mod(ki, round.EC().Params().N)

	var R edwards25519.ExtendedGroupElement
	riBytes := bigIntToEncodedBytes(ki)
	edwards25519.GeScalarMultBase(&R, riBytes)

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		rhoj := new(big.Int).SetBytes(
			common.SHA512_256([]byte(strconv.Itoa(j)), round.temp.m.Bytes(), common.SHA512_256(B)),
		)
		rhoj.Mod(rhoj, round.EC().Params().N)

		D := round.pre.DEs[j].D
		E := round.pre.DEs[j].E

		Rj, err := E.ScalarMult(rhoj).Add(D)
		if err != nil {
			return round.WrapError(fmt.Errorf("rho * E + D err: %s", err.Error()), Pj)
		}
		round.temp.Rj[j] = Rj

		Rj = Rj.EightInvEight()
		if err != nil {
			return round.WrapError(errors.Wrapf(err, "NewECPoint(Rj)"), Pj)
		}

		extendedRj := ecPointToExtendedElement(round.EC(), Rj.X(), Rj.Y(), round.Rand())
		R = addExtendedElements(R, extendedRj)
	}

	// compute lambda
	var encodedR [32]byte
	R.ToBytes(&encodedR)

	encodedPubKey := ecPointToEncodedBytes(round.temp.pubW.X(), round.temp.pubW.Y())

	// h = hash512(R || X || M)
	h := sha512.New()
	h.Reset()
	h.Write(encodedR[:])
	h.Write(encodedPubKey[:])
	if round.temp.fullBytesLen == 0 {
		h.Write(round.temp.m.Bytes())
	} else {
		var mBytes = make([]byte, round.temp.fullBytesLen)
		round.temp.m.FillBytes(mBytes)
		h.Write(mBytes)
	}

	var lambda [64]byte
	h.Sum(lambda[:0])
	var lambdaReduced [32]byte
	edwards25519.ScReduce(&lambdaReduced, &lambda)

	// compute si
	var localS [32]byte
	edwards25519.ScMulAdd(&localS, &lambdaReduced, bigIntToEncodedBytes(round.temp.wi), riBytes)

	round.temp.c = encodedBytesToBigInt(&lambdaReduced)
	round.temp.si = &localS
	round.temp.r = encodedBytesToBigInt(&encodedR)

	// broadcast si to other parties
	common.Logger.Debugf("P[%d]: round_2 broadcast", i)
	r2msg := sign.NewSignRound2Message(round.PartyID(), encodedBytesToBigInt(&localS))
	round.temp.signRound1Messages[i] = r2msg
	round.out <- r2msg

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound1Messages {
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

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*sign.SignRound2Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
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
