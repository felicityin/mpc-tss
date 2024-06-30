// Copyright © 2019 Binance

package sign

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/felicityin/mpc-tss/cggmp/non_threshold/auxiliary"
	"github.com/felicityin/mpc-tss/cggmp/non_threshold/keygen"
	"github.com/felicityin/mpc-tss/cggmp/non_threshold/test"
	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/tss"
)

const (
	testParticipants = 3
	testThreshold    = 3
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}

	// only for test
	tss.SetCurve(tss.S256())
}

func TestE2EConcurrent(t *testing.T) {
	setUp("debug")

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(keygen.Ecdsa, testThreshold, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold, len(keys))
	assert.Equal(t, testThreshold, len(signPIDs))

	auxs, _, err := auxiliary.LoadAuxTestFixtures(keygen.Ecdsa, testThreshold)
	assert.NoError(t, err, "should load aux fixtures")
	assert.Equal(t, testThreshold, len(auxs))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater
	msg := big.NewInt(42)

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		P := NewLocalParty(msg, params, keys[i], auxs[i], outCh, endCh).(*LocalParty)
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
				x := new(big.Int)
				for _, Pj := range parties {
					xj := Pj.keys.PrivXi
					gXj := crypto.ScalarBaseMult(tss.S256(), xj)
					BigXj := Pj.keys.PubXj[Pj.PartyID().Index]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")

					x = x.Add(x, Pj.keys.PrivXi)
				}

				x = new(big.Int).Mod(x, tss.S256().Params().N)

				xG := crypto.ScalarBaseMult(tss.S256(), x)
				assert.True(t, xG.Equals(keys[0].Pubkey), "ensure X == g^x")

				t.Logf("Done. Received signature data from %d participants", ended)
				R := parties[0].temp.R
				r := parties[0].temp.R.X()
				fmt.Printf("sign result: R(%s, %s), r=%s\n", R.X().String(), R.Y().String(), r.String())

				modN := common.ModInt(tss.S256().Params().N)

				// BEGIN check s correctness
				sumS := big.NewInt(0)
				for _, p := range parties {
					sumS = modN.Add(sumS, p.temp.si)
				}
				fmt.Printf("S: %s\n", sumS.String())
				// END check s correctness

				// BEGIN ECDSA verify
				pk := ecdsa.PublicKey{
					Curve: tss.S256(),
					X:     keys[0].Pubkey.X(),
					Y:     keys[0].Pubkey.Y(),
				}
				ok := ecdsa.Verify(&pk, msg.Bytes(), R.X(), sumS)
				assert.True(t, ok, "ecdsa verify must pass")
				t.Log("ECDSA signing test done.")
				// END ECDSA verify

				break SIGN
			}
		}
	}
}

func TestE2EConcurrentWithLeadingZeroInMSG(t *testing.T) {
	setUp("debug")

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(keygen.Ecdsa, testThreshold, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold, len(keys))
	assert.Equal(t, testThreshold, len(signPIDs))

	auxs, _, err := auxiliary.LoadAuxTestFixtures(keygen.Ecdsa, testThreshold)
	assert.NoError(t, err, "should load aux fixtures")
	assert.Equal(t, testThreshold, len(auxs))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg, _ := hex.DecodeString("00f163ee51bcaeff9cdff5e0e3c1a646abd19885fffbab0b3b4236e0cf95c9f5")
	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)
		P := NewLocalParty(new(big.Int).SetBytes(msg), params, keys[i], auxs[i], outCh, endCh, len(msg)).(*LocalParty)
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
				R := parties[0].temp.R
				r := parties[0].temp.R.X()
				fmt.Printf("sign result: R(%s, %s), r=%s\n", R.X().String(), R.Y().String(), r.String())

				modN := common.ModInt(tss.S256().Params().N)

				// BEGIN check s correctness
				sumS := big.NewInt(0)
				for _, p := range parties {
					sumS = modN.Add(sumS, p.temp.si)
				}
				fmt.Printf("S: %s\n", sumS.String())
				// END check s correctness

				// BEGIN ECDSA verify
				pkX, pkY := keys[0].Pubkey.X(), keys[0].Pubkey.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}
				ok := ecdsa.Verify(&pk, msg, R.X(), sumS)
				assert.True(t, ok, "ecdsa verify must pass")
				t.Log("ECDSA signing test done.")
				// END ECDSA verify

				break SIGN
			}
		}
	}
}
