package signing

import (
	"crypto/sha512"
	"fmt"
	"math/big"

	"github.com/agl/ed25519/edwards25519"
	"github.com/pkg/errors"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/protocols/cggmp/eddsa/presign"
	"github.com/felicityin/mpc-tss/protocols/cggmp/eddsa/sign"
	"github.com/felicityin/mpc-tss/protocols/cggmp/keygen"
	"github.com/felicityin/mpc-tss/protocols/utils"
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

	round.number = 1
	round.started = true
	round.resetOK()

	round.temp.ssidNonce = new(big.Int).SetUint64(0)
	var err error
	round.temp.ssid, err = round.getSSID()
	if err != nil {
		return round.WrapError(err)
	}

	i := round.PartyID().Index
	common.Logger.Infof("[sign] party: %d, round_3 start", i)

	riBytes := bigIntToEncodedBytes(round.pre.K)
	encodedR := bigIntToEncodedBytes(round.pre.R)
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

	// store message pieces
	round.temp.si = &localS

	// broadcast si to other parties
	r1msg := sign.NewSignRound3Message(round.PartyID(), encodedBytesToBigInt(&localS))
	round.temp.signRound1Messages[i] = r1msg
	round.out <- r1msg

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
	if _, ok := msg.Content().(*sign.SignRound3Message); ok {
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
		round.temp.pubW = round.key.Pubkey
	} else {
		privXi := round.key.PrivXi
		ks := round.key.Ks
		pubXjs := round.key.PubXj

		if round.Threshold()+1 > len(ks) {
			return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
		}

		wi, _, pubKey, err := utils.PrepareForSigning(round.Params().EC(), i, len(ks), privXi, ks, pubXjs)
		if err != nil {
			return err
		}

		round.temp.wi = wi
		round.temp.pubW = pubKey
	}
	return nil
}
