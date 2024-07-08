// Copyright © 2019 Binance

package presign

import (
	"encoding/json"
	"os"
	"sync/atomic"
	"testing"

	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/protocols/cggmp/auxiliary"
	"github.com/felicityin/mpc-tss/protocols/cggmp/keygen"
	nonKeygen "github.com/felicityin/mpc-tss/protocols/cggmp/keygen/non_threshold"
	tKeygen "github.com/felicityin/mpc-tss/protocols/cggmp/keygen/threshold"
	"github.com/felicityin/mpc-tss/protocols/cggmp/test"
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
	tss.SetCurve(tss.S256())
}

func TestE2ENonThresholdConcurrent(t *testing.T) {
	setUp("debug")

	threshold := testParticipants

	// PHASE: load keygen fixtures
	keys, signPIDs, err := nonKeygen.LoadKeygenTestFixturesRandomSet(keygen.Ecdsa, threshold, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, threshold, len(keys))
	assert.Equal(t, threshold, len(signPIDs))

	auxs, _, err := auxiliary.LoadAuxTestFixtures(keygen.Ecdsa, threshold)
	assert.NoError(t, err, "should load aux fixtures")
	assert.Equal(t, threshold, len(auxs))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *LocalPartySaveData, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		P := NewLocalParty(false, params, keys[i], auxs[i], outCh, endCh).(*LocalParty)
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

		case save := <-endCh:
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			tryWriteTestFixtureFile(t, false, keygen.Ecdsa, index, *save)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", ended)
				t.Log("ECDSA signing test done.")
				// END ECDSA verify
				break SIGN
			}
		}
	}
}

func TestE2EThresholdConcurrent(t *testing.T) {
	setUp("debug")

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := tKeygen.LoadKeygenTestFixturesRandomSet(keygen.Ecdsa, testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")

	auxs, _, err := auxiliary.LoadAuxTestFixtures(keygen.Ecdsa, testThreshold+1)
	assert.NoError(t, err, "should load aux fixtures")

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *LocalPartySaveData, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)
		P := NewLocalParty(true, params, keys[i], auxs[i], outCh, endCh).(*LocalParty)
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

		case save := <-endCh:
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			tryWriteTestFixtureFile(t, true, keygen.Ecdsa, index, *save)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Log("ECDSA signing test done.")
				// END ECDSA verify
				break SIGN
			}
		}
	}
}

func tryWriteTestFixtureFile(t *testing.T, isThreshold bool, kind, index int, data LocalPartySaveData) {
	fixtureFileName := makeTestFixtureFilePath(isThreshold, kind, index)

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
