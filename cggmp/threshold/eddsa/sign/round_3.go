package sign

import (
	"crypto/sha512"
	"math/big"

	"github.com/agl/ed25519/edwards25519"
	"github.com/pkg/errors"

	"github.com/felicityin/mpc-tss/common"
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

	var R edwards25519.ExtendedGroupElement
	riBytes := bigIntToEncodedBytes(round.temp.k)
	edwards25519.GeScalarMultBase(&R, riBytes)

	// verify received log proof and compute R
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		msg := round.temp.signRound2Messages[j]
		r2msg := msg.Content().(*SignRound2Message)

		logProof, err := r2msg.UnmarshalLogProof(round.Params().EC())
		if err != nil {
			common.Logger.Errorf("failed to unmarshal log proof: %s, party: %d", err, j)
			return round.WrapError(errors.New("failed to unmarshal log proof"), Pj)
		}
		common.Logger.Debugf("P[%d]: receive P[%d]'s log proof", i, j)

		Rj, err := r2msg.UnmarshalR(round.EC())
		if err != nil {
			common.Logger.Errorf("unmarshal R failed: %s, party: %d", err, j)
			return round.WrapError(err)
		}

		contextJ := append(round.temp.ssid, big.NewInt(int64(j)).Bytes()...)

		err = logProof.Verify(
			ProofParameter, contextJ, round.temp.kCiphertexts[j],
			round.aux.PaillierPKs[j].N, round.aux.PedersenPKs[i], Rj, nil,
		)
		if err != nil {
			common.Logger.Errorf("verify log proof failed: %s, party: %d", err, j)
			return round.WrapError(err)
		}
		common.Logger.Debugf("P[%d]: verify P[%d]'s log proof ok", i, j)

		Rj = Rj.EightInvEight()
		if err != nil {
			return round.WrapError(errors.Wrapf(err, "NewECPoint(Rj)"), Pj)
		}

		extendedRj := ecPointToExtendedElement(round.Params().EC(), Rj.X(), Rj.Y(), round.Rand())
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

	// store r3 message pieces
	round.temp.si = &localS
	round.temp.r = encodedBytesToBigInt(&encodedR)

	// broadcast si to other parties
	r3msg := NewSignRound3Message(round.PartyID(), encodedBytesToBigInt(&localS))
	round.temp.signRound3Messages[i] = r3msg
	round.out <- r3msg

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
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
