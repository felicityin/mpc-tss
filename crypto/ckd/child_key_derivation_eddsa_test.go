package ckd

import (
	"encoding/hex"
	"math/big"
	"testing"

	edwards "github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/stretchr/testify/assert"

	"mpc_tss/common"
	"mpc_tss/crypto"
)

func TestDerivation(t *testing.T) {
	priKeyBytes, err := hex.DecodeString("ae1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f241")
	assert.NoError(t, err)
	chainCode, err := hex.DecodeString("be1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f242")
	assert.NoError(t, err)
	priKey := new(big.Int).SetBytes(priKeyBytes)
	pubKey := crypto.ScalarBaseMult(edwards.Edwards(), priKey)
	deduceKey, _ := pubKey.Add(pubKey)

	childPrivKey, childPubKey, err := DeriveEddsaChildPrivKey(priKey, pubKey, deduceKey, chainCode, "81/0/0/35/0")
	assert.NoError(t, err)

	childPubKeyPt, err := DeriveEddsaChildPubKey(pubKey, deduceKey, chainCode, "81/0/0/35/0")
	assert.NoError(t, err)

	tmp := crypto.ScalarBaseMult(edwards.Edwards(), new(big.Int).SetBytes(childPrivKey[:]))
	assert.Equal(t, tmp.X(), childPubKeyPt.X())
	assert.Equal(t, tmp.Y(), childPubKeyPt.Y())

	childPubKeyBytes := edwards.NewPublicKey(childPubKeyPt.X(), childPubKeyPt.Y()).Serialize()
	assert.Equal(t, childPubKey, childPubKeyBytes)

	sk, pk, err := edwards.PrivKeyFromScalar(common.PadToLengthBytesInPlace(childPrivKey[:], 32))
	assert.NoError(t, err)
	assert.Equal(t, pk.X, childPubKeyPt.X())

	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}

	r, s, err := edwards.Sign(sk, data)
	assert.NoError(t, err, "sign should not throw an error")

	pk1 := edwards.PublicKey{
		Curve: edwards.Edwards(),
		X:     childPubKeyPt.X(),
		Y:     childPubKeyPt.Y(),
	}
	ok := edwards.Verify(&pk1, data, r, s)
	assert.True(t, ok)
	assert.NoError(t, err)
}

func TestTss(t *testing.T) {
	chainCode, _ := hex.DecodeString("be1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f242")

	rootKeySkBytes1, _ := hex.DecodeString("ae1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f241")
	rootKeySkBytes2, _ := hex.DecodeString("ae1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f242")
	rootKeySkBytes3, _ := hex.DecodeString("ae1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f243")

	rootSk1 := new(big.Int).SetBytes(rootKeySkBytes1)
	rootSk2 := new(big.Int).SetBytes(rootKeySkBytes2)
	rootSk3 := new(big.Int).SetBytes(rootKeySkBytes3)

	rootPk1 := crypto.ScalarBaseMult(edwards.Edwards(), rootSk1)
	rootPk2 := crypto.ScalarBaseMult(edwards.Edwards(), rootSk2)
	rootPk3 := crypto.ScalarBaseMult(edwards.Edwards(), rootSk3)

	rootSk := big.NewInt(0)
	rootSk.Add(rootSk, rootSk1)
	rootSk.Mod(rootSk, edwards.Edwards().N)
	rootSk.Add(rootSk, rootSk2)
	rootSk.Mod(rootSk, edwards.Edwards().N)
	rootSk.Add(rootSk, rootSk3)
	rootSk.Mod(rootSk, edwards.Edwards().N)

	rootPk := rootPk1
	rootPk, _ = rootPk.Add(rootPk2)
	rootPk, _ = rootPk.Add(rootPk3)

	rootSkPk := crypto.ScalarBaseMult(edwards.Edwards(), rootSk)
	assert.Equal(t, rootSkPk.X(), rootPk.X())
	assert.Equal(t, rootSkPk.Y(), rootPk.Y())

	deduceKey, _ := rootPk1.Add(rootPk1)
	childPrivKey1, _, _ := DeriveEddsaChildPrivKey(rootSk1, rootPk1, deduceKey, chainCode, "81/0/0/35/0")
	childPubKeyPt1, _ := DeriveEddsaChildPubKey(rootPk1, deduceKey, chainCode, "81/0/0/35/0")
	childPrivKey2, _, _ := DeriveEddsaChildPrivKey(rootSk1, rootPk1, deduceKey, chainCode, "81/0/0/35/0")
	childPubKeyPt2, _ := DeriveEddsaChildPubKey(rootPk1, deduceKey, chainCode, "81/0/0/35/0")
	childPrivKey3, _, _ := DeriveEddsaChildPrivKey(rootSk1, rootPk1, deduceKey, chainCode, "81/0/0/35/0")
	childPubKeyPt3, _ := DeriveEddsaChildPubKey(rootPk1, deduceKey, chainCode, "81/0/0/35/0")

	tmp := crypto.ScalarBaseMult(edwards.Edwards(), new(big.Int).SetBytes(childPrivKey1[:]))
	assert.Equal(t, tmp.X(), childPubKeyPt1.X())
	assert.Equal(t, tmp.Y(), childPubKeyPt1.Y())

	childSk := big.NewInt(0)
	childSk.Add(childSk, new(big.Int).SetBytes(childPrivKey1[:]))
	childSk.Mod(childSk, edwards.Edwards().N)
	childSk.Add(childSk, new(big.Int).SetBytes(childPrivKey2[:]))
	childSk.Mod(childSk, edwards.Edwards().N)
	childSk.Add(childSk, new(big.Int).SetBytes(childPrivKey3[:]))
	childSk.Mod(childSk, edwards.Edwards().N)

	childPk := childPubKeyPt1
	childPk, _ = childPk.Add(childPubKeyPt2)
	childPk, _ = childPk.Add(childPubKeyPt3)

	sk, pk, err := edwards.PrivKeyFromScalar(childSk.Bytes())
	assert.NoError(t, err)
	assert.Equal(t, pk.X, childPk.X())

	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}

	r, s, err := edwards.Sign(sk, data)
	assert.NoError(t, err, "sign should not throw an error")

	pk1 := edwards.PublicKey{
		Curve: edwards.Edwards(),
		X:     childPk.X(),
		Y:     childPk.Y(),
	}
	ok := edwards.Verify(&pk1, data, r, s)
	assert.True(t, ok)
	assert.NoError(t, err)
}
