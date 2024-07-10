// Copyright © 2019 Binance

package signing

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/agl/ed25519/edwards25519"
	edwards "github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/protocols/cggmp/keygen"
	nonKeygen "github.com/felicityin/mpc-tss/protocols/cggmp/keygen/non_threshold"
	tKeygen "github.com/felicityin/mpc-tss/protocols/cggmp/keygen/threshold"
	"github.com/felicityin/mpc-tss/protocols/cggmp/test"
	"github.com/felicityin/mpc-tss/protocols/frost/presign"
	"github.com/felicityin/mpc-tss/tss"
)

const (
	testParticipants = 3
	testThreshold    = 2
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}

	// only for test
	tss.SetCurve(tss.Edwards())
}

func TestE2ENonThresholdConcurrent(t *testing.T) {
	setUp("debug")

	threshold := testParticipants

	// PHASE: load keygen fixtures
	keys, signPIDs, err := nonKeygen.LoadKeygenTestFixturesRandomSet(keygen.Eddsa, threshold, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, threshold, len(keys))
	assert.Equal(t, threshold, len(signPIDs))

	pres, _, err := presign.LoadPreTestFixtures(false, threshold)
	assert.NoError(t, err, "should load aux fixtures")
	assert.Equal(t, threshold, len(pres))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater
	msg := big.NewInt(200)
	path := "0/1/2/2/10"

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, signPIDs[i], len(signPIDs), threshold)
		party, err := NewLocalParty(msg, false, params, path, keys[i], pres[i], outCh, endCh)
		assert.NoError(t, err)
		P := party.(*LocalParty)
		parties = append(parties, P)

		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
SIGN:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break SIGN

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				common.Logger.Debugf("recv brodcast msg from %d", msg.GetFrom().Index)
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				common.Logger.Debugf("recv p2p msg from %d, send to %d", msg.GetFrom().Index, dest[0].Index)
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", ended)
				R := parties[0].temp.r

				// BEGIN check s correctness
				sumS := parties[0].temp.si
				for i, p := range parties {
					if i == 0 {
						continue
					}

					var tmpSumS [32]byte
					edwards25519.ScMulAdd(&tmpSumS, sumS, bigIntToEncodedBytes(big.NewInt(1)), p.temp.si)
					sumS = &tmpSumS
				}
				fmt.Printf("S: %s\n", encodedBytesToBigInt(sumS).String())
				fmt.Printf("R: %s\n", R.String())
				// END check s correctness

				// BEGIN EDDSA verify
				pkX, pkY := parties[0].keys.Pubkey.X(), parties[0].keys.Pubkey.Y()
				pk := edwards.PublicKey{
					Curve: tss.Edwards(),
					X:     pkX,
					Y:     pkY,
				}

				newSig, err := edwards.ParseSignature(parties[0].data.Signature)
				if err != nil {
					println("new sig error, ", err.Error())
				}

				ok := edwards.Verify(&pk, msg.Bytes(), newSig.R, newSig.S)
				assert.True(t, ok, "eddsa verify must pass")
				t.Log("EDDSA signing test done.")
				// END EDDSA verify

				break SIGN
			}
		}
	}
}

func TestE2EThresholdConcurrent(t *testing.T) {
	setUp("info")

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := tKeygen.LoadKeygenTestFixturesRandomSet(keygen.Eddsa, threshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")

	pres, _, err := presign.LoadPreTestFixtures(true, testThreshold+1)
	assert.NoError(t, err, "should load aux fixtures")

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater
	msg, _ := hex.DecodeString("00f163ee51bcaeff9cdff5e0e3c1a646abd19885fffbab0b3b4236e0cf95c9f5")
	path := "0/1/2/2/10"

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, signPIDs[i], len(signPIDs), threshold)
		party, err := NewLocalParty(new(big.Int).SetBytes(msg), true, params, path, keys[i], pres[i], outCh, endCh, len(msg))
		assert.NoError(t, err)
		P := party.(*LocalParty)
		parties = append(parties, P)

		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
signing:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				common.Logger.Debugf("recv brodcast msg from %d", msg.GetFrom().Index)
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				common.Logger.Debugf("recv p2p msg from %d, send to", msg.GetFrom().Index, dest[0].Index)
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", ended)
				R := parties[0].temp.r

				// BEGIN check s correctness
				sumS := parties[0].temp.si
				for i, p := range parties {
					if i == 0 {
						continue
					}

					var tmpSumS [32]byte
					edwards25519.ScMulAdd(&tmpSumS, sumS, bigIntToEncodedBytes(big.NewInt(1)), p.temp.si)
					sumS = &tmpSumS
				}
				fmt.Printf("S: %s\n", encodedBytesToBigInt(sumS).String())
				fmt.Printf("R: %s\n", R.String())
				// END check s correctness

				// BEGIN EDDSA verify
				pkX, pkY := parties[0].keys.Pubkey.X(), parties[0].keys.Pubkey.Y()
				pk := edwards.PublicKey{
					Curve: tss.Edwards(),
					X:     pkX,
					Y:     pkY,
				}

				newSig, err := edwards.ParseSignature(parties[0].data.Signature)
				if err != nil {
					println("new sig error, ", err.Error())
				}

				ok := edwards.Verify(&pk, msg, newSig.R, newSig.S)
				assert.True(t, ok, "eddsa verify must pass")
				t.Log("EDDSA signing test done.")
				// END EDDSA verify

				break signing
			}
		}
	}
}
