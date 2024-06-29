package auxiliary

import (
	"encoding/json"
	"math/big"
	"os"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"mpc_tss/cggmp/non_threshold/keygen"
	"mpc_tss/cggmp/non_threshold/test"
	"mpc_tss/common"
	"mpc_tss/crypto/paillier"
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

func TestE2EPreConcurrentWithPre(t *testing.T) {
	big1 := big.NewInt(1)
	P, _ := new(big.Int).SetString("104975615121222854384410219330480259027041155688835759631647658735069527864919393410352284436544267374160206678331198777612866309766581999589789442827625308608614590850591998897357449886061863686453412019330757447743487422636807387508460941025550338019105820406950462187693188000168607236389735877001362796259", 10)
	Q, _ := new(big.Int).SetString("102755306389915984635356782597494195047102560555160692696207839728487252530690043689166546890155633162017964085393843240989395317546293846694693801865924045225783240995686020308553449158438908412088178393717793204697268707791329981413862246773904710409946848630083569401668855899757371993960961231481357354607", 10)
	N := new(big.Int).Mul(P, Q)

	// phiN = P-1 * Q-1
	PMinus1, QMinus1 := new(big.Int).Sub(P, big1), new(big.Int).Sub(Q, big1)
	phiN := new(big.Int).Mul(PMinus1, QMinus1)

	// lambdaN = lcm(P−1, Q−1)
	gcd := new(big.Int).GCD(nil, nil, PMinus1, QMinus1)
	lambdaN := new(big.Int).Div(phiN, gcd)

	publicKey := &paillier.PublicKey{N: N}
	privateKey := &paillier.PrivateKey{PublicKey: *publicKey, LambdaN: lambdaN, PhiN: phiN, P: P, Q: Q}

	testEcdsaE2EConcurrentAndSaveFixtures(t, keygen.Ecdsa, privateKey)
}

func TestEcdsaE2EConcurrentAndSaveFixtures(t *testing.T) {
	testEcdsaE2EConcurrentAndSaveFixtures(t, keygen.Ecdsa, nil)
}

func TestEddsaE2EConcurrentAndSaveFixtures(t *testing.T) {
	testEcdsaE2EConcurrentAndSaveFixtures(t, keygen.Eddsa, nil)
}

func testEcdsaE2EConcurrentAndSaveFixtures(t *testing.T, kind int, sk *paillier.PrivateKey) {
	setUp("debug")

	threshold := testThreshold

	_, pIDs, err := keygen.LoadKeygenTestFixturesRandomSet(kind, testThreshold, testParticipants)
	if err != nil {
		common.Logger.Error("No keygen test fixtures were found")
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
		params := tss.NewParameters(nil, p2pCtx, pIDs[i], len(pIDs), threshold)
		P := NewLocalParty(params, outCh, endCh).(*LocalParty)
		P.data.PaillierSK = sk
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
AUX:
	for {
		common.Logger.Debugf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break AUX

		case msg := <-outCh:
			bz, _, _ := msg.WireBytes()
			pMsg, _ := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
			switch pMsg.Content().(type) {
			case *AuxRound1Message:
				common.Logger.Debugf("AuxRound1Message")
			case *AuxRound2Message:
				common.Logger.Debugf("AuxRound2Message")
			case *AuxRound3Message:
				common.Logger.Debugf("AuxRound3Message")
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

				t.Logf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())
				break AUX
			}
		}
	}
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
