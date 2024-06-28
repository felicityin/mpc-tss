package ckd

import (
	"errors"
	"fmt"
	"math/big"

	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"

	"mpc_tss/common"
	"mpc_tss/crypto"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/edwards/v2"
)

func DeriveEddsaChildPrivKey(
	privkey *big.Int,
	pubkey *crypto.ECPoint,
	deducePubkey *crypto.ECPoint,
	codeByte []byte,
	path string,
) (childPrivKey [32]byte, childPubKey []byte, err error) {
	var buf [32]byte
	privkeyBytes := privkey.FillBytes(buf[:])

	extendedKey := NewExtendKeyD(privkeyBytes, pubkey, deducePubkey, 0, 0, codeByte)

	childPrivKey, childPubKey, err = DerivePrivateKeyForPathD(extendedKey, path, edwards.Edwards())
	if err != nil {
		return childPrivKey, nil, fmt.Errorf("derive child private err: %s", err.Error())
	}
	return childPrivKey, childPubKey, nil
}

func DeriveEddsaChildPubKey(
	srcEcPoint, deduceEcPoint *crypto.ECPoint,
	codeByte []byte,
	path string,
) (childPubKeyPoint *crypto.ECPoint, err error) {
	extendedKey := NewExtendKeyD(nil, srcEcPoint, deduceEcPoint, 0, 0, codeByte)

	childPubKeyPoint, err1 := DerivePublicKeyForPathD(extendedKey, path, edwards.Edwards())
	if err1 != nil {
		return nil, fmt.Errorf("derive child private err: %s", err.Error())
	}
	return
}

type ExtendedKeyD struct {
	PublicKey    *crypto.ECPoint
	DeducePubKey *crypto.ECPoint
	Depth        uint8
	ChildIndex   uint32
	PrivKey      []byte // 32 bytes
	ChainCode    []byte // 32 bytes
	ParentFP     []byte // parent fingerprint
	Version      []byte
}

func NewExtendKeyD(
	privKey []byte,
	pubKeyPoint,
	deducePubkeyPoint *crypto.ECPoint,
	index uint32,
	depth uint8,
	chainCode []byte,
) *ExtendedKeyD {
	var parentFP []byte
	pkPublicKeyBytes := serializeCompressed(deducePubkeyPoint.X(), deducePubkeyPoint.Y())
	parentFP = hash160(pkPublicKeyBytes)[:4]
	return &ExtendedKeyD{
		PrivKey:      privKey,
		PublicKey:    pubKeyPoint,
		DeducePubKey: deducePubkeyPoint,
		Depth:        depth,
		ChildIndex:   index,
		ChainCode:    chainCode,
		ParentFP:     parentFP,
		Version:      []byte{0},
	}
}

// DerivePrivateKeyForPath derives the private key by following the BIP 32/44 path from privKeyBytes,
// using the given chainCode.
func DerivePrivateKeyForPathD(pk *ExtendedKeyD, path string, curve elliptic.Curve) ([32]byte, []byte, error) {
	extPk := pk
	parts := strings.Split(path, "/")
	if pk.Depth > 0 {
		parts = parts[pk.Depth:]
	}
	for _, part := range parts {
		// do we have an apostrophe?
		harden := part[len(part)-1:] == "'"
		if harden {
			part = part[:len(part)-1]
		}
		// harden == private derivation, else public derivation:
		idx, err := strconv.Atoi(part)
		if err != nil {
			return [32]byte{}, nil, fmt.Errorf("invalid BIP 32 path: %s", err)
		}
		if idx < 0 {
			return [32]byte{}, nil, errors.New("invalid BIP 32 path: index negative ot too large")
		}
		_, extPk, err = DeriveChildKeyD(uint32(idx), harden, extPk, curve)
		if err != nil {
			return [32]byte{}, nil, fmt.Errorf("DeriveChildKey error: %s", err)
		}
	}
	var derivedKey [32]byte
	childPrivKeyBytes := extPk.PrivKey
	padLen := len(childPrivKeyBytes)
	for ; padLen < 32; padLen++ {
		childPrivKeyBytes = append([]byte{0}, childPrivKeyBytes...)
	}
	n := copy(derivedKey[:], childPrivKeyBytes[:])
	if n != 32 || len(childPrivKeyBytes) != 32 {
		return [32]byte{}, nil, fmt.Errorf("expected a key of length 32, got length: %v", len(childPrivKeyBytes))
	}
	pubKeyBytes := edwards.NewPublicKey(extPk.PublicKey.X(), extPk.PublicKey.Y()).Serialize()
	return derivedKey, pubKeyBytes[:], nil
}

// DeriveChildKey Derive a child key from the given parent key. The function returns "IL" ("I left"), per BIP-32 spec. It also
// returns the derived child key.
func DeriveChildKeyD(index uint32, harden bool, pk *ExtendedKeyD, curve elliptic.Curve) (*big.Int, *ExtendedKeyD, error) {
	if index >= HardenedKeyStart {
		return nil, nil, errors.New("the index must be non-hardened")
	}
	if pk.Depth == maxDepth {
		return nil, nil, errors.New("cannot derive key beyond max depth")
	}

	// this can't return an error:
	pkPublicKeyBytes := serializeCompressed(pk.DeducePubKey.X(), pk.DeducePubKey.Y())
	var data []byte
	if harden {
		index = index | 0x80000000
		data = append([]byte{byte(0)}, pk.PrivKey[:]...)
	} else {
		data = pkPublicKeyBytes
	}
	data = append(data, uint32ToBytes(index)...)

	// I = HMAC-SHA512(Key = chainCode, Data=data)
	hmac512 := hmac.New(sha512.New, pk.ChainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)
	il := ilr[:32]
	childChainCode := ilr[32:]
	ilNum := new(big.Int).SetBytes(il)
	ilNum = ilNum.Mod(ilNum, curve.Params().N)

	if ilNum.Cmp(curve.Params().N) >= 0 || ilNum.Sign() == 0 {
		// falling outside of the valid range for curve private keys
		common.Logger.Error("error deriving child key")
		return nil, nil, errors.New("invalid derived key")
	}

	deltaG := crypto.ScalarBaseMult(curve, ilNum)
	if deltaG.X().Sign() == 0 || deltaG.Y().Sign() == 0 {
		common.Logger.Error("error invalid child")
		return nil, nil, errors.New("invalid child")
	}
	childCryptoPk, err := pk.PublicKey.Add(deltaG)
	if err != nil {
		common.Logger.Error("error adding delta G to parent key")
		return nil, nil, err
	}
	deduceCryptoPk, err := pk.DeducePubKey.Add(deltaG)
	if err != nil {
		common.Logger.Error("error adding delta G to parent key")
		return nil, nil, err
	}

	privKey := new(big.Int).SetBytes(pk.PrivKey)
	sInt := new(big.Int).Add(ilNum, privKey)
	x := sInt.Mod(sInt, curve.Params().N)

	childPk := &ExtendedKeyD{
		PrivKey:      x.Bytes(),
		PublicKey:    childCryptoPk,
		DeducePubKey: deduceCryptoPk,
		Depth:        pk.Depth + 1,
		ChildIndex:   index,
		ChainCode:    childChainCode,
		ParentFP:     hash160(pkPublicKeyBytes)[:4],
		Version:      pk.Version,
	}
	return ilNum, childPk, nil
}

// DerivePublicKeyForPath derives the public key by following the BIP 32/44 path from privKeyBytes,
// using the given chainCode.
func DerivePublicKeyForPathD(pk *ExtendedKeyD, path string, curve elliptic.Curve) (*crypto.ECPoint, error) {
	extPk := pk
	parts := strings.Split(path, "/")
	if pk.Depth > 0 {
		parts = parts[pk.Depth:]
	}
	for _, part := range parts {
		// do we have an apostrophe?
		harden := part[len(part)-1:] == "'"
		if harden {
			return nil, fmt.Errorf("harden not suppored")
		}
		// harden == private derivation, else public derivation:
		idx, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid BIP 32 path: %s", err)
		}
		if idx < 0 {
			return nil, errors.New("invalid BIP 32 path: index negative ot too large")
		}
		_, extPk, err = DeriveChildPubKeyD(uint32(idx), extPk, curve)
		if err != nil {
			return nil, fmt.Errorf("invalid BIP 32 path: %s", err)
		}
	}
	pubkeyPoint, err := crypto.NewECPoint(curve, extPk.PublicKey.X(), extPk.PublicKey.Y())
	if err != nil {
		return nil, fmt.Errorf("invalid extPk.PublicKey: %v, err %v", extPk.PublicKey, err)
	}
	return pubkeyPoint, nil
}

// DeriveChildPubKey Derive a child public key from the given parent key. The function returns "IL" ("I left"), per BIP-32 spec. It also
// returns the derived child public key.
func DeriveChildPubKeyD(index uint32, pk *ExtendedKeyD, curve elliptic.Curve) (*big.Int, *ExtendedKeyD, error) {
	if index >= HardenedKeyStart {
		return nil, nil, errors.New("the index must be non-hardened")
	}
	if pk.Depth == maxDepth {
		return nil, nil, errors.New("cannot derive key beyond max depth")
	}

	// this can't return an error:
	pkPublicKeyBytes := serializeCompressed(pk.DeducePubKey.X(), pk.DeducePubKey.Y())
	var data []byte
	data = pkPublicKeyBytes

	data = append(data, uint32ToBytes(index)...)

	// I = HMAC-SHA512(Key = chainCode, Data=data)
	hmac512 := hmac.New(sha512.New, pk.ChainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)
	il := ilr[:32]
	childChainCode := ilr[32:]
	ilNum := new(big.Int).SetBytes(il)
	ilNum = ilNum.Mod(ilNum, curve.Params().N)

	if ilNum.Cmp(curve.Params().N) >= 0 || ilNum.Sign() == 0 {
		// falling outside of the valid range for curve private keys
		common.Logger.Error("error deriving child key")
		return nil, nil, errors.New("invalid derived key")
	}

	deltaG := crypto.ScalarBaseMult(curve, ilNum)
	if deltaG.X().Sign() == 0 || deltaG.Y().Sign() == 0 {
		common.Logger.Error("error invalid child")
		return nil, nil, errors.New("invalid child")
	}
	childCryptoPk, err := pk.PublicKey.Add(deltaG)
	if err != nil {
		common.Logger.Error("error adding delta G to parent key")
		return nil, nil, err
	}
	deduceChildCryptoPk, err := pk.DeducePubKey.Add(deltaG)
	if err != nil {
		common.Logger.Error("error adding delta G to parent key")
		return nil, nil, err
	}

	childPk := &ExtendedKeyD{
		PrivKey:      nil,
		PublicKey:    childCryptoPk,
		DeducePubKey: deduceChildCryptoPk,
		Depth:        pk.Depth + 1,
		ChildIndex:   index,
		ChainCode:    childChainCode,
		ParentFP:     hash160(pkPublicKeyBytes)[:4],
		Version:      pk.Version,
	}
	return ilNum, childPk, nil
}
