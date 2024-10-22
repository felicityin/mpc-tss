package sign

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/tss"
)

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	common.Logger.Infof("[sign] party: %d, round final start", i)

	sumS := new(big.Int).Set(round.temp.si)

	for j := range round.Parties().IDs() {
		round.ok[j] = true
		if j == i {
			continue
		}

		r4msg := round.temp.signRound4Messages[j].Content().(*SignRound4Message)

		sumS.Add(sumS, r4msg.UnmarshalS())
		sumS.Mod(sumS, round.EC().Params().N)
	}

	recid := 0
	// byte v = if(R.X > curve.N) then 2 else 0) | (if R.Y.IsEven then 0 else 1);
	if round.temp.R.X().Cmp(round.Params().EC().Params().N) > 0 {
		recid = 2
	}
	if round.temp.R.Y().Bit(0) != 0 {
		recid |= 1
	}

	// This is copied from:
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L442-L444
	// This is needed because of tendermint checks here:
	// https://github.com/tendermint/tendermint/blob/d9481e3648450cb99e15c6a070c1fb69aa0c255b/crypto/secp256k1/secp256k1_nocgo.go#L43-L47
	secp256k1halfN := new(big.Int).Rsh(round.Params().EC().Params().N, 1)
	if sumS.Cmp(secp256k1halfN) > 0 {
		sumS.Sub(round.Params().EC().Params().N, sumS)
		recid ^= 1
	}

	// save the signature for final output
	bitSizeInBytes := round.Params().EC().Params().BitSize / 8
	round.data.R = padToLengthBytesInPlace(round.temp.R.X().Bytes(), bitSizeInBytes)
	round.data.S = padToLengthBytesInPlace(sumS.Bytes(), bitSizeInBytes)
	round.data.Signature = append(round.data.R, round.data.S...)
	round.data.SignatureRecovery = []byte{byte(recid)}
	if round.temp.fullBytesLen == 0 {
		round.data.M = round.temp.msg.Bytes()
	} else {
		var mBytes = make([]byte, round.temp.fullBytesLen)
		round.temp.msg.FillBytes(mBytes)
		round.data.M = mBytes
	}

	pk := ecdsa.PublicKey{
		Curve: round.Params().EC(),
		X:     round.key.Pubkey.X(),
		Y:     round.key.Pubkey.Y(),
	}

	ok := ecdsa.Verify(&pk, round.data.M, round.temp.R.X(), sumS)
	if !ok {
		return round.WrapError(fmt.Errorf("signature verification failed"))
	}

	round.end <- round.data
	return nil
}

func (round *finalization) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}

func padToLengthBytesInPlace(src []byte, length int) []byte {
	oriLen := len(src)
	if oriLen < length {
		for i := 0; i < length-oriLen; i++ {
			src = append([]byte{0}, src...)
		}
	}
	return src
}
