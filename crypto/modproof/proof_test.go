// Copyright © 2019-2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package modproof_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	. "github.com/felicityin/mpc-tss/crypto/modproof"
	"github.com/felicityin/mpc-tss/crypto/paillier"

	"github.com/stretchr/testify/assert"
)

var Session = []byte("session")

var (
	privateKey *paillier.PrivateKey
	publicKey  *paillier.PublicKey
)

const (
	testPaillierKeyLength = 2048
)

func setUp(t *testing.T) {
	if privateKey != nil && publicKey != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var err error
	privateKey, publicKey, err = paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)
}

func TestMod(test *testing.T) {
	setUp(test)
	P, Q, N := privateKey.P, privateKey.Q, privateKey.N

	proof, err := NewProof(Session, N, P, Q, rand.Reader)
	assert.NoError(test, err)

	proofBzs := proof.Bytes()
	proof, err = NewProofFromBytes(proofBzs[:])
	assert.NoError(test, err)

	ok := proof.Verify(Session, N)
	assert.True(test, ok, "proof must verify")
}
