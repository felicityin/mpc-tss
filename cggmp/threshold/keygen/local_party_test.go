// Copyright © 2019 Binance

package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"os"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/felicityin/mpc-tss/cggmp/non_threshold/test"
	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/crypto/vss"
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
}

func TestEcdsaE2EConcurrentAndSaveFixtures(t *testing.T) {
	testE2EConcurrentAndSaveFixtures(t, Ecdsa)
}

func TestEddsaE2EConcurrentAndSaveFixtures(t *testing.T) {
	testE2EConcurrentAndSaveFixtures(t, Eddsa)
}

func testE2EConcurrentAndSaveFixtures(t *testing.T, kind int) {
	setUp("debug")

	threshold := testThreshold
	_, pIDs, err := LoadKeygenTestFixtures(kind, testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan *LocalPartySaveData, len(pIDs))

	updater := test.SharedPartyUpdater

	startGR := runtime.NumGoroutine()

	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var params *tss.Parameters
		if kind == Ecdsa {
			params = tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), threshold)
		} else {
			params = tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], len(pIDs), threshold)
		}
		P := NewLocalParty(params, outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	// PHASE: keygen
	var ended int32
keygen:
	for {
		common.Logger.Debugf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break keygen

		case msg := <-outCh:
			bz, _, _ := msg.WireBytes()
			pMsg, _ := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
			switch pMsg.Content().(type) {
			case *TKgRound1Message:
				common.Logger.Debugf("KGRound1Message")
			case *TKgRound2Message1:
				common.Logger.Debugf("KGRound2Message1")
			case *TKgRound2Message2:
				common.Logger.Debugf("KGRound2Message2")
			case *TKgRound3Message:
				common.Logger.Debugf("KGRound3Message")
			}

			dest := msg.GetTo()
			common.Logger.Debugf("reveive msg from %d", msg.GetFrom().Index)

			if dest == nil { // broadcast!
				common.Logger.Debugf("reveive broadcast msg from %d", msg.GetFrom().Index)
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						common.Logger.Debugf("P.PartyID().Index == msg.GetFrom().Index, index: %d", msg.GetFrom().Index)
						continue
					}
					common.Logger.Debugf("update, index: %d", msg.GetFrom().Index)
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				common.Logger.Debugf("reveive p2p msg from %d", msg.GetFrom().Index)
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			common.Logger.Debugf("reveive save data")

			// SAVE a test fixture file for this P (if it doesn't already exist)
			// .. here comes a workaround to recover this party's index (it was removed from save data)
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			tryWriteTestFixtureFile(t, kind, index, *save)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				verifyKeygen(t, kind, threshold, parties, save)

				t.Log("ECDSA signing test done.")
				t.Logf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())

				break keygen
			}
		}
	}
}

func verifyKeygen(t *testing.T, kind, threshold int, parties []*LocalParty, save *LocalPartySaveData) {
	var ec elliptic.Curve
	if kind == Ecdsa {
		ec = tss.S256()
	} else {
		ec = tss.Edwards()
	}

	// combine shares for each Pj to get u
	u := big.NewInt(0)
	for j, Pj := range parties {
		pShares := make(vss.Shares, 0)
		for _, P := range parties {
			vssMsgs := P.temp.kgRound2Message2s
			share := vssMsgs[j].Content().(*TKgRound2Message2).Share
			shareStruct := &vss.Share{
				Threshold: threshold,
				ID:        P.PartyID().KeyInt(),
				Share:     new(big.Int).SetBytes(share),
			}
			pShares = append(pShares, shareStruct)
		}
		uj, err := pShares[:threshold+1].ReConstruct(ec)
		assert.NoError(t, err, "vss.ReConstruct should not throw error")

		// uG test: u*G[j] == V[0]
		assert.Equal(t, uj, Pj.temp.s0)
		uG := crypto.ScalarBaseMult(ec, uj)
		assert.True(t, uG.Equals(Pj.temp.vs[0]), "ensure u*G[j] == V_0")

		// xj tests: BigXj == xj*G
		xj := Pj.data.PrivXi
		gXj := crypto.ScalarBaseMult(ec, xj)
		BigXj := Pj.data.PubXj[j]
		assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")

		// fails if threshold cannot be satisfied (bad share)
		{
			badShares := pShares[:threshold]
			badShares[len(badShares)-1].Share.Set(big.NewInt(0))
			uj, err := pShares[:threshold].ReConstruct(ec)
			assert.NoError(t, err)
			assert.NotEqual(t, parties[j].temp.s0, uj)
			BigXjX, BigXjY := ec.ScalarBaseMult(uj.Bytes())
			assert.NotEqual(t, BigXjX, Pj.temp.vs[0].X())
			assert.NotEqual(t, BigXjY, Pj.temp.vs[0].Y())
		}
		u = new(big.Int).Add(u, uj)
		u.Mod(u, ec.Params().N)

		// make sure everyone has the same chain code
		assert.Equal(t, parties[0].data.ChainCode, Pj.data.ChainCode)
	}

	pkX, pkY := save.Pubkey.X(), save.Pubkey.Y()

	// public key tests
	assert.NotZero(t, u, "u should not be zero")
	ourPkX, ourPkY := ec.ScalarBaseMult(u.Bytes())
	assert.Equal(t, pkX, ourPkX, "pkX should match expected pk derived from u")
	assert.Equal(t, pkY, ourPkY, "pkY should match expected pk derived from u")
	t.Log("Public key tests done.")

	// make sure everyone has the same public key
	for _, Pj := range parties {
		assert.Equal(t, pkX, Pj.data.Pubkey.X())
		assert.Equal(t, pkY, Pj.data.Pubkey.Y())
	}
	t.Log("Public key distribution test done.")

	if kind == Ecdsa {
		verifyEcdsa(t, save, u)
	} else {
		verifyEddsa(t, save, u)
	}
}

func verifyEcdsa(t *testing.T, save *LocalPartySaveData, u *big.Int) {
	// build key pair
	pkX, pkY := save.Pubkey.X(), save.Pubkey.Y()
	pk := ecdsa.PublicKey{
		Curve: tss.EC(),
		X:     pkX,
		Y:     pkY,
	}
	sk := ecdsa.PrivateKey{
		PublicKey: pk,
		D:         u,
	}

	// test pub key, should be on curve and match pkX, pkY
	assert.True(t, pk.IsOnCurve(pkX, pkY), "public key must be on curve")

	// test sign/verify
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}
	r, s, err := ecdsa.Sign(rand.Reader, &sk, data)
	assert.NoError(t, err, "sign should not throw an error")
	ok := ecdsa.Verify(&pk, data, r, s)
	assert.True(t, ok, "signature should be ok")
}

func verifyEddsa(t *testing.T, save *LocalPartySaveData, u *big.Int) {
	pkX, pkY := save.Pubkey.X(), save.Pubkey.Y()
	pk := edwards.PublicKey{
		Curve: tss.Edwards(),
		X:     pkX,
		Y:     pkY,
	}
	sk, _, err := edwards.PrivKeyFromScalar(common.PadToLengthBytesInPlace(u.Bytes(), 32))
	if !assert.NoError(t, err) {
		return
	}

	// test pub key, should be on curve and match pkX, pkY
	assert.True(t, pk.IsOnCurve(pkX, pkY), "public key must be on curve")

	// test sign/verify
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}
	r, s, err := edwards.Sign(sk, data)
	assert.NoError(t, err, "sign should not throw an error")
	ok := edwards.Verify(&pk, data, r, s)
	assert.True(t, ok, "signature should be ok")
	t.Log("EDDSA signing test done.")
}

func tryWriteTestFixtureFile(t *testing.T, kind, index int, data LocalPartySaveData) {
	fixtureFileName := makeTestFixtureFilePath(kind, index)

	// fixture file does not already exist?
	// if it does, we won't re-create it here
	fi, err := os.Stat(fixtureFileName)
	if !(err == nil && fi != nil && !fi.IsDir()) {
		fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			assert.NoErrorf(t, err, "unable to open fixture file %s for writing", fixtureFileName)
		}
		bz, err := json.Marshal(&data)
		if err != nil {
			t.Fatalf("unable to marshal save data for fixture file %s", fixtureFileName)
		}
		_, err = fd.Write(bz)
		if err != nil {
			t.Fatalf("unable to write to fixture file %s", fixtureFileName)
		}
		t.Logf("Saved a test fixture file for party %d: %s", index, fixtureFileName)
	} else {
		t.Logf("Fixture file already exists for party %d; not re-creating: %s", index, fixtureFileName)
	}
	//
}
