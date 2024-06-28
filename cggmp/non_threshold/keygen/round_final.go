package keygen

import (
	"encoding/hex"
	"errors"
	"math/big"

	"mpc_tss/common"
	"mpc_tss/crypto/schnorr"
	"mpc_tss/tss"
)

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round 4 already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("party: %d, round_4 start", i)

	for j, msg := range round.temp.kgRound3Messages {
		if j == i {
			continue
		}

		common.Logger.Debugf("round_4 calc challenge")
		challenge := common.RejectionSample(
			round.EC().Params().N,
			common.SHA512_256i_TAGGED(
				append(round.temp.ssid, round.temp.srid...),
				big.NewInt(int64(j)),
				round.save.PubXj[j].X(),
				round.save.PubXj[j].Y(),
				round.temp.payload[j].commitedA.X(),
				round.temp.payload[j].commitedA.Y(),
			),
		)

		common.Logger.Debugf("round_4 get proof")

		schProof := schnorr.Proof{Proof: msg.Content().(*KGRound3Message).UnmarshalSchProof()}

		common.Logger.Debugf("round_4 verify proof")

		if !schProof.Verify(round.temp.payload[j].commitedA, round.save.PubXj[j], challenge) {
			common.Logger.Errorf("schnorr proof verify failed, party: %d", j)
			return round.WrapError(errors.New("schnorr proof verify failed"))
		}
	}

	// Compute and SAVE the public key
	pubKey := round.save.PubXj[0]
	var err error
	for j, pubx := range round.save.PubXj {
		common.Logger.Infof("%d, pubkey: (%d, %d)", j, pubx.X(), pubx.Y())
		if j == 0 {
			continue
		}
		pubKey, err = pubKey.Add(pubx)
		if err != nil {
			common.Logger.Errorf("calc pubkey failed, party: %d", j)
			return round.WrapError(err)
		}
	}
	round.save.Pubkey = pubKey

	pubkeySum := hex.EncodeToString(round.save.Pubkey.X().Bytes()) + "|" + hex.EncodeToString(round.save.Pubkey.Y().Bytes())
	common.Logger.Infof("key sum: %s", pubkeySum)

	common.Logger.Infof("party: %d, round_4 save", i)
	round.end <- round.save

	return nil
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *round4) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *round4) NextRound() tss.Round {
	return nil // finished!
}
