// Copyright © Swingby

package ckd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"mpc_tss/tss"
	"strconv"
	"strings"

	"mpc_tss/common"
	"mpc_tss/crypto"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

type ExtendedKey struct {
	PublicKey    ecdsa.PublicKey
	DeducePubKey ecdsa.PublicKey
	Depth        uint8
	ChildIndex   uint32
	PrivKey      []byte // 32 bytes
	ChainCode    []byte // 32 bytes
	ParentFP     []byte // parent fingerprint
	Version      []byte
}

// For more information about child key derivation see https://github.com/binance-chain/tss-lib/issues/104
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki .
// The functions below do not implement the full BIP-32 specification. As mentioned in the Jira ticket above,
// we only use non-hardened derived keys.

const (

	// HardenedKeyStart hardened key starts.
	HardenedKeyStart = 0x80000000 // 2^31

	// max Depth
	maxDepth = 1<<8 - 1

	PubKeyBytesLenCompressed = 33

	pubKeyCompressed byte = 0x2

	serializedKeyLen = 78

	// MinSeedBytes is the minimum number of bytes allowed for a seed to
	// a master node.
	MinSeedBytes = 16 // 128 bits

	// MaxSeedBytes is the maximum number of bytes allowed for a seed to
	// a master node.
	MaxSeedBytes = 64 // 512 bits
)

// Extended public key serialization, defined in BIP32
func (k *ExtendedKey) String() string {
	// version(4) || depth(1) || parentFP (4) || childinde(4) || chaincode (32) || key(33) || checksum(4)
	var childNumBytes [4]byte
	binary.BigEndian.PutUint32(childNumBytes[:], k.ChildIndex)

	serializedBytes := make([]byte, 0, serializedKeyLen+4)
	serializedBytes = append(serializedBytes, k.Version...)
	serializedBytes = append(serializedBytes, k.Depth)
	serializedBytes = append(serializedBytes, k.ParentFP...)
	serializedBytes = append(serializedBytes, childNumBytes[:]...)
	serializedBytes = append(serializedBytes, k.ChainCode...)
	pubKeyBytes := serializeCompressed(k.PublicKey.X, k.PublicKey.Y)
	serializedBytes = append(serializedBytes, pubKeyBytes...)

	checkSum := doubleHashB(serializedBytes)[:4]
	serializedBytes = append(serializedBytes, checkSum...)
	return base58.Encode(serializedBytes)
}

// NewExtendedKeyFromString returns a new extended key from a base58-encoded extended key
func NewExtendedKeyFromString(key string, curve elliptic.Curve) (*ExtendedKey, error) {
	// version(4) || depth(1) || parentFP (4) || childinde(4) || chaincode (32) || key(33) || checksum(4)

	decoded := base58.Decode(key)
	if len(decoded) != serializedKeyLen+4 {
		return nil, errors.New("invalid extended key")
	}

	// Split the payload and checksum up and ensure the checksum matches.
	payload := decoded[:len(decoded)-4]
	checkSum := decoded[len(decoded)-4:]
	expectedCheckSum := doubleHashB(payload)[:4]
	if !bytes.Equal(checkSum, expectedCheckSum) {
		return nil, errors.New("invalid extended key")
	}

	// Deserialize each of the payload fields.
	version := payload[:4]
	depth := payload[4:5][0]
	parentFP := payload[5:9]
	childNum := binary.BigEndian.Uint32(payload[9:13])
	chainCode := payload[13:45]
	keyData := payload[45:78]

	var pubKey ecdsa.PublicKey

	if c, ok := curve.(*btcec.KoblitzCurve); ok {
		// Ensure the public key parses correctly and is actually on the
		// secp256k1 curve.
		pk, err := btcec.ParsePubKey(keyData, c)
		if err != nil {
			return nil, err
		}
		pubKey = ecdsa.PublicKey(*pk)
	} else {
		px, py := elliptic.Unmarshal(curve, keyData)
		pubKey = ecdsa.PublicKey{
			Curve: curve,
			X:     px,
			Y:     py,
		}
	}

	return &ExtendedKey{
		PublicKey:  pubKey,
		Depth:      depth,
		ChildIndex: childNum,
		ChainCode:  chainCode,
		ParentFP:   parentFP,
		Version:    version,
	}, nil
}

func doubleHashB(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}

func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

func hash160(buf []byte) []byte {
	return calcHash(calcHash(buf, sha256.New()), ripemd160.New())
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

// PaddedAppend append src to dst, if less than size padding 0 at start
func paddedAppend(dst []byte, srcPaddedSize int, src []byte) []byte {
	return append(dst, paddedBytes(srcPaddedSize, src)...)
}

// PaddedBytes padding byte array to size length
func paddedBytes(size int, src []byte) []byte {
	offset := size - len(src)
	tmp := src
	if offset > 0 {
		tmp = make([]byte, size)
		copy(tmp[offset:], src)
	}
	return tmp
}

// SerializeCompressed serializes a public key 33-byte compressed format
func serializeCompressed(publicKeyX *big.Int, publicKeyY *big.Int) []byte {
	b := make([]byte, 0, PubKeyBytesLenCompressed)
	format := pubKeyCompressed
	if isOdd(publicKeyY) {
		format |= 0x1
	}
	b = append(b, format)
	return paddedAppend(b, 32, publicKeyX.Bytes())
}

func DeriveChildKeyFromHierarchy(indicesHierarchy []uint32, pk *ExtendedKey, mod *big.Int, curve elliptic.Curve) (*big.Int, *ExtendedKey, error) {
	var k = pk
	var err error
	var childKey *ExtendedKey
	mod_ := common.ModInt(mod)
	ilNum := big.NewInt(0)
	for index := range indicesHierarchy {
		ilNumOld := ilNum
		ilNum, childKey, err = DeriveChildKey(indicesHierarchy[index], false, k, curve)
		if err != nil {
			return nil, nil, err
		}
		k = childKey
		ilNum = mod_.Add(ilNum, ilNumOld)
	}
	return ilNum, k, nil
}

// DeriveChildKey Derive a child key from the given parent key. The function returns "IL" ("I left"), per BIP-32 spec. It also
// returns the derived child key.
func DeriveChildKey(index uint32, harden bool, pk *ExtendedKey, curve elliptic.Curve) (*big.Int, *ExtendedKey, error) {
	if index >= HardenedKeyStart {
		return nil, nil, errors.New("the index must be non-hardened")
	}
	if pk.Depth == maxDepth {
		return nil, nil, errors.New("cannot derive key beyond max depth")
	}

	cryptoPk, err := crypto.NewECPoint(curve, pk.PublicKey.X, pk.PublicKey.Y)
	if err != nil {
		common.Logger.Error("error getting pubkey from extendedkey")
		fmt.Errorf("error getting pubkey from extendedkey")
		return nil, nil, err
	}
	deducePk, err := crypto.NewECPoint(curve, pk.DeducePubKey.X, pk.DeducePubKey.Y)
	if err != nil {
		common.Logger.Error("error getting deduce pubkey from extendedkey")
		fmt.Errorf("error getting deduce pubkey from extendedkey")
		return nil, nil, err
	}

	// this can't return an error:
	pkPublicKeyBytes := serializeCompressed(pk.DeducePubKey.X, pk.DeducePubKey.Y)
	var data []byte
	if harden {
		index = index | 0x80000000
		data = append([]byte{byte(0)}, pk.PrivKey[:]...)
	} else {
		data = pkPublicKeyBytes

		/* By using btcec, we can remove the dependency on tendermint/crypto/secp256k1
		pubkey := secp256k1.PrivKeySecp256k1(privKeyBytes).PubKey()
		public := pubkey.(secp256k1.PubKeySecp256k1)
		data = public[:]
		*/
	}
	data = append(data, uint32ToBytes(index)...)

	// I = HMAC-SHA512(Key = chainCode, Data=data)
	hmac512 := hmac.New(sha512.New, pk.ChainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)
	il := ilr[:32]
	childChainCode := ilr[32:]
	ilNum := new(big.Int).SetBytes(il)

	if ilNum.Cmp(curve.Params().N) >= 0 || ilNum.Sign() == 0 {
		// falling outside of the valid range for curve private keys
		err = errors.New("invalid derived key")
		common.Logger.Error("error deriving child key")
		return nil, nil, err
	}

	deltaG := crypto.ScalarBaseMult(curve, ilNum)
	if deltaG.X().Sign() == 0 || deltaG.Y().Sign() == 0 {
		err = errors.New("invalid child")
		common.Logger.Error("error invalid child")
		return nil, nil, err
	}
	childCryptoPk, err := cryptoPk.Add(deltaG)
	if err != nil {
		common.Logger.Error("error adding delta G to parent key")
		return nil, nil, err
	}
	deduceCryptoPk, err := deducePk.Add(deltaG)
	if err != nil {
		common.Logger.Error("error adding delta G to parent key")
		return nil, nil, err
	}

	privKey := big.NewInt(0).SetBytes(pk.PrivKey)
	sInt := new(big.Int).Add(ilNum, privKey)
	x := sInt.Mod(sInt, btcec.S256().N)

	childPk := &ExtendedKey{
		PrivKey:      x.Bytes(),
		PublicKey:    *childCryptoPk.ToECDSAPubKey(),
		DeducePubKey: *deduceCryptoPk.ToECDSAPubKey(),
		Depth:        pk.Depth + 1,
		ChildIndex:   index,
		ChainCode:    childChainCode,
		ParentFP:     hash160(pkPublicKeyBytes)[:4],
		Version:      pk.Version,
	}
	return ilNum, childPk, nil
}

// DeriveChildPubKey Derive a child public key from the given parent key. The function returns "IL" ("I left"), per BIP-32 spec. It also
// returns the derived child public key.
func DeriveChildPubKey(index uint32, pk *ExtendedKey, curve elliptic.Curve) (*big.Int, *ExtendedKey, error) {
	if index >= HardenedKeyStart {
		return nil, nil, errors.New("the index must be non-hardened")
	}
	if pk.Depth == maxDepth {
		return nil, nil, errors.New("cannot derive key beyond max depth")
	}

	cryptoPk, err := crypto.NewECPoint(curve, pk.PublicKey.X, pk.PublicKey.Y)
	if err != nil {
		common.Logger.Error("error getting pubkey from extendedkey")
		return nil, nil, err
	}
	deducePk, err := crypto.NewECPoint(curve, pk.DeducePubKey.X, pk.DeducePubKey.Y)
	if err != nil {
		common.Logger.Error("error getting deduce pubkey from extendedkey")
		return nil, nil, err
	}

	// this can't return an error:
	pkPublicKeyBytes := serializeCompressed(pk.DeducePubKey.X, pk.DeducePubKey.Y)
	var data []byte
	data = pkPublicKeyBytes

	/* By using btcec, we can remove the dependency on tendermint/crypto/secp256k1
	pubkey := secp256k1.PrivKeySecp256k1(privKeyBytes).PubKey()
	public := pubkey.(secp256k1.PubKeySecp256k1)
	data = public[:]
	*/
	data = append(data, uint32ToBytes(index)...)

	// I = HMAC-SHA512(Key = chainCode, Data=data)
	hmac512 := hmac.New(sha512.New, pk.ChainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)
	il := ilr[:32]
	childChainCode := ilr[32:]
	ilNum := new(big.Int).SetBytes(il)

	if ilNum.Cmp(curve.Params().N) >= 0 || ilNum.Sign() == 0 {
		// falling outside of the valid range for curve private keys
		err = errors.New("invalid derived key")
		common.Logger.Error("error deriving child key")
		return nil, nil, err
	}

	deltaG := crypto.ScalarBaseMult(curve, ilNum)
	if deltaG.X().Sign() == 0 || deltaG.Y().Sign() == 0 {
		err = errors.New("invalid child")
		common.Logger.Error("error invalid child")
		return nil, nil, err
	}
	childCryptoPk, err := cryptoPk.Add(deltaG)
	if err != nil {
		common.Logger.Error("error adding delta G to parent key")
		return nil, nil, err
	}
	deduceChildCryptoPk, err := deducePk.Add(deltaG)
	if err != nil {
		common.Logger.Error("error adding delta G to parent key")
		return nil, nil, err
	}

	/*	privKey := big.NewInt(0).SetBytes(pk.PrivKey)     //we don't have the parent private key
		sInt := new(big.Int).Add(ilNum, privKey)
		x := sInt.Mod(sInt, btcec.S256().N)*/

	childPk := &ExtendedKey{
		PrivKey:      nil,
		PublicKey:    *childCryptoPk.ToECDSAPubKey(),
		DeducePubKey: *deduceChildCryptoPk.ToECDSAPubKey(),
		Depth:        pk.Depth + 1,
		ChildIndex:   index,
		ChainCode:    childChainCode,
		ParentFP:     hash160(pkPublicKeyBytes)[:4],
		Version:      pk.Version,
	}
	return ilNum, childPk, nil
}

func uint32ToBytes(i uint32) []byte {
	b := [4]byte{}
	binary.BigEndian.PutUint32(b[:], i)
	return b[:]
}

func NewExtendKey(privKey []byte, pubKeyPoint, deducePubkeyPoint *crypto.ECPoint, index uint32, depth uint8, chainCode []byte) *ExtendedKey {
	var parentFP []byte
	pkPublicKeyBytes := serializeCompressed(deducePubkeyPoint.X(), deducePubkeyPoint.Y())
	parentFP = hash160(pkPublicKeyBytes)[:4]
	return &ExtendedKey{
		PrivKey:      privKey,
		PublicKey:    *pubKeyPoint.ToECDSAPubKey(),
		DeducePubKey: *deducePubkeyPoint.ToECDSAPubKey(),
		Depth:        depth,
		ChildIndex:   index,
		ChainCode:    chainCode,
		ParentFP:     parentFP,
		Version:      []byte{0},
	}
}

// DerivePrivateKeyForPath derives the private key by following the BIP 32/44 path from privKeyBytes,
// using the given chainCode.
func DerivePrivateKeyForPath(pk *ExtendedKey, path string) ([32]byte, []byte, error) {
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
		_, extPk, err = DeriveChildKey(uint32(idx), harden, extPk, tss.S256())
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
		return [32]byte{}, nil, fmt.Errorf("expected a (secp256k1) key of length 32, got length: %v", len(childPrivKeyBytes))
	}
	pubKeyBytes := serializeCompressed(extPk.PublicKey.X, extPk.PublicKey.Y)
	return derivedKey, pubKeyBytes, nil
}

// DerivePublicKeyForPath derives the public key by following the BIP 32/44 path from privKeyBytes,
// using the given chainCode.
func DerivePublicKeyForPath(pk *ExtendedKey, path string) (*crypto.ECPoint, error) {
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
		_, extPk, err = DeriveChildPubKey(uint32(idx), extPk, tss.S256())
		if err != nil {
			return nil, fmt.Errorf("invalid BIP 32 path: %s", err)
		}
	}
	pubkeyPoint, err := crypto.NewECPoint(tss.S256(), extPk.PublicKey.X, extPk.PublicKey.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid extPk.PublicKey: %v, err %v", extPk.PublicKey, err)
	}
	return pubkeyPoint, nil
}
