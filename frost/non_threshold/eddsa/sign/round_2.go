package sign

import (
	"crypto/sha512"
	"fmt"
	"math/big"
	"strconv"

	"github.com/agl/ed25519/edwards25519"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"

	"github.com/felicityin/mpc-tss/common"
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
	common.Logger.Infof("[sign] party: %d, round_2 start", i)

	var B []byte

	for j, Pj := range round.Parties().IDs() {
		msg := round.temp.signRound1Messages[j]
		r1msg := msg.Content().(*SignRound1Message)

		bs, err := proto.Marshal(r1msg)
		if err != nil {
			return round.WrapError(fmt.Errorf("marshal round1 msg err: %s", err.Error()), Pj)
		}

		B = append(B, round.key.PubXj[j].X().Bytes()...)
		B = append(B, bs...)
	}

	rhoi := new(big.Int).SetBytes(
		common.SHA512_256([]byte(strconv.Itoa(i)), round.temp.m.Bytes(), common.SHA512_256(B)),
	)
	rhoi.Mod(rhoi, round.EC().Params().N)

	ki := new(big.Int).Mul(round.temp.e, rhoi)
	ki.Add(ki, round.temp.d)
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

		msg := round.temp.signRound1Messages[j]
		r1msg := msg.Content().(*SignRound1Message)

		D, err := r1msg.UnmarshalD()
		if err != nil {
			common.Logger.Errorf("failed to unmarshal D: %s, party: %d", err, j)
			return round.WrapError(errors.New("failed to unmarshal D"), Pj)
		}

		E, err := r1msg.UnmarshalE()
		if err != nil {
			common.Logger.Errorf("failed to unmarshal E: %s, party: %d", err, j)
			return round.WrapError(errors.New("failed to unmarshal E"), Pj)
		}

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

	encodedPubKey := ecPointToEncodedBytes(round.key.Pubkey.X(), round.key.Pubkey.Y())

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
	edwards25519.ScMulAdd(&localS, &lambdaReduced, bigIntToEncodedBytes(round.key.PrivXi), riBytes)

	round.temp.c = encodedBytesToBigInt(&lambdaReduced)
	round.temp.si = &localS
	round.temp.r = encodedBytesToBigInt(&encodedR)

	// broadcast si to other parties
	common.Logger.Debugf("P[%d]: round_2 broadcast", i)
	r2msg := NewSignRound2Message(round.PartyID(), encodedBytesToBigInt(&localS))
	round.temp.signRound2Messages[i] = r2msg
	round.out <- r2msg

	return nil
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

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound2Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
