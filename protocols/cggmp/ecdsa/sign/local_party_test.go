// Copyright © 2019 Binance

package sign

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"runtime"
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
	testParticipants = 5
	testThreshold    = 4
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
	endCh := make(chan *common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater
	msg := big.NewInt(42)
	path := "0/1/2/2/10"

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)
		party, err := NewLocalParty(msg, false, params, path, keys[i], auxs[i], outCh, endCh)
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
					X:     parties[0].keys.Pubkey.X(),
					Y:     parties[0].keys.Pubkey.Y(),
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
	endCh := make(chan *common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg, _ := hex.DecodeString("00f163ee51bcaeff9cdff5e0e3c1a646abd19885fffbab0b3b4236e0cf95c9f5")
	path := "0/1/2/2/10"

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)
		party, err := NewLocalParty(new(big.Int).SetBytes(msg), true, params, path, keys[i], auxs[i], outCh, endCh, len(msg))
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
				common.Logger.Debugf("recv p2p msg from %d, send to", msg.GetFrom().Index, dest[0].Index)
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
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
					X:     parties[0].keys.Pubkey.X(),
					Y:     parties[0].keys.Pubkey.Y(),
				}
				ok := ecdsa.Verify(&pk, msg, R.X(), sumS)
				assert.True(t, ok, "ecdsa verify must pass")
				t.Log("ECDSA signing test done.")
				// END ECDSA verify

				break SIGN
			}
		}
	}

	readMem()
}

func readMem() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// fmt.Println(ms) // 太复杂了

	// 内存 通义千问
	// 打印一些关键的内存统计信息
	fmt.Printf("Alloc = %v MiB\n", m.Alloc/1024/1024)           // 分配但未释放的内存
	fmt.Printf("TotalAlloc = %v MiB\n", m.TotalAlloc/1024/1024) // 程序启动以来分配的总内存
	fmt.Printf("Sys = %v MiB\n", m.Sys/1024/1024)               // 从操作系统分配的总内存
	fmt.Printf("HeapAlloc = %v MiB\n", m.HeapAlloc/1024/1024)   // 从堆上分配但未释放的内存
	fmt.Printf("HeapSys = %v MiB\n", m.HeapSys/1024/1024)       // 由Go分配的堆内存的系统内存大小
	fmt.Printf("NumGC = %v\n", m.NumGC)                         // 进行的GC次数
}
