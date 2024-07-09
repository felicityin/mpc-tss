package presign

import (
	"math/big"

	"github.com/agl/ed25519/edwards25519"
	"github.com/pkg/errors"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/protocols/cggmp/eddsa/sign"
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
	riBytes := bigIntToEncodedBytes(round.save.K)
	edwards25519.GeScalarMultBase(&R, riBytes)

	// verify received log proof and compute R
	for j, Pj := range round.Parties().IDs() {
		round.ok[j] = true
		if j == i {
			continue
		}

		msg := round.temp.signRound2Messages[j]
		r2msg := msg.Content().(*sign.SignRound2Message)

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

		extendedRj := ecPointToExtendedElement(round.EC(), Rj.X(), Rj.Y(), round.Rand())
		R = addExtendedElements(R, extendedRj)
	}

	// compute lambda
	var encodedR [32]byte
	R.ToBytes(&encodedR)
	round.save.R = encodedBytesToBigInt(&encodedR)

	round.end <- round.save
	return nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *round3) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *round3) NextRound() tss.Round {
	return nil // finished!
}
