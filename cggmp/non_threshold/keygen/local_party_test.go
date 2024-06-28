package keygen

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"os"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"mpc_tss/cggmp/non_threshold/test"
	"mpc_tss/common"
	"mpc_tss/crypto"
	"mpc_tss/tss"
)

const (
	testParticipants = 2
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
Keygen:
	for {
		common.Logger.Debugf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break Keygen

		case msg := <-outCh:
			bz, _, _ := msg.WireBytes()
			pMsg, _ := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
			switch pMsg.Content().(type) {
			case *KGRound1Message:
				common.Logger.Debugf("KGRound1Message")
			case *KGRound2Message:
				common.Logger.Debugf("KGRound2Message")
			case *KGRound3Message:
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

				if kind == Ecdsa {
					verifyEcdsa(t, parties, save)
				} else {
					verifyEddsa(t, parties, save)
				}

				t.Logf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())
				break Keygen
			}
		}
	}
}

func verifyEcdsa(t *testing.T, parties []*LocalParty, save *LocalPartySaveData) {
	x := new(big.Int)
	for _, Pj := range parties {
		xj := Pj.data.PrivXi
		gXj := crypto.ScalarBaseMult(tss.S256(), xj)
		BigXj := Pj.data.PubXj[Pj.PartyID().Index]
		assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")

		x = x.Add(x, Pj.data.PrivXi)
	}

	x = new(big.Int).Mod(x, tss.S256().Params().N)
	scalar := make([]byte, 0, 32)
	copy(scalar, x.Bytes())

	xG := crypto.ScalarBaseMult(tss.S256(), x)
	assert.True(t, xG.Equals(save.Pubkey), "ensure X == g^x")

	// build ecdsa key pair
	pkX, pkY := save.Pubkey.X(), save.Pubkey.Y()
	pk := ecdsa.PublicKey{
		Curve: tss.EC(),
		X:     pkX,
		Y:     pkY,
	}
	sk := ecdsa.PrivateKey{
		PublicKey: pk,
		D:         x,
	}
	// test pub key, should be on curve and match pkX, pkY
	assert.True(t, sk.IsOnCurve(pkX, pkY), "public key must be on curve")

	// public key tests
	assert.NotZero(t, x, "x should not be zero")
	ourPkX, ourPkY := tss.EC().ScalarBaseMult(x.Bytes())
	assert.Equal(t, pkX, ourPkX, "pkX should match expected pk derived from u")
	assert.Equal(t, pkY, ourPkY, "pkY should match expected pk derived from u")
	t.Log("Public key tests done.")

	// make sure everyone has the same ECDSA public key
	for _, Pj := range parties {
		assert.Equal(t, pkX, Pj.data.Pubkey.X())
		assert.Equal(t, pkY, Pj.data.Pubkey.Y())
	}
	t.Log("Public key distribution test done.")

	// test sign/verify
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}
	r, s, err := ecdsa.Sign(rand.Reader, &sk, data)
	assert.NoError(t, err, "sign should not throw an error")
	ok := ecdsa.Verify(&pk, data, r, s)
	assert.True(t, ok, "signature should be ok")
	t.Log("ECDSA signing test done.")
}

func verifyEddsa(t *testing.T, parties []*LocalParty, save *LocalPartySaveData) {
	x := new(big.Int)
	for _, Pj := range parties {
		xj := Pj.data.PrivXi
		gXj := crypto.ScalarBaseMult(tss.Edwards(), xj)
		BigXj := Pj.data.PubXj[Pj.PartyID().Index]
		assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")

		x = x.Add(x, Pj.data.PrivXi)
	}

	x = new(big.Int).Mod(x, tss.Edwards().Params().N)
	scalar := make([]byte, 0, 32)
	copy(scalar, x.Bytes())

	xG := crypto.ScalarBaseMult(tss.Edwards(), x)
	assert.True(t, xG.Equals(save.Pubkey), "ensure X == g^x")

	// build eddsa key pair
	pkX, pkY := save.Pubkey.X(), save.Pubkey.Y()
	pk := edwards.PublicKey{
		Curve: tss.Edwards(),
		X:     pkX,
		Y:     pkY,
	}
	sk, _, err := edwards.PrivKeyFromScalar(common.PadToLengthBytesInPlace(x.Bytes(), 32))
	if !assert.NoError(t, err) {
		return
	}

	// test pub key, should be on curve and match pkX, pkY
	assert.True(t, pk.IsOnCurve(pkX, pkY), "public key must be on curve")

	// public key tests
	assert.NotZero(t, x, "x should not be zero")
	ourPkX, ourPkY := tss.Edwards().ScalarBaseMult(x.Bytes())
	assert.Equal(t, pkX, ourPkX, "pkX should match expected pk derived from x")
	assert.Equal(t, pkY, ourPkY, "pkY should match expected pk derived from x")
	t.Log("Public key tests done.")

	// make sure everyone has the same EDDSA public key
	for _, Pj := range parties {
		assert.Equal(t, pkX, Pj.data.Pubkey.X())
		assert.Equal(t, pkY, Pj.data.Pubkey.Y())
	}
	t.Log("Public key distribution test done.")

	// make sure everyone has the same EDDSA public key
	for _, Pj := range parties {
		assert.Equal(t, pkX, Pj.data.Pubkey.X())
		assert.Equal(t, pkY, Pj.data.Pubkey.Y())
	}
	t.Log("Public key distribution test done.")

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
}
