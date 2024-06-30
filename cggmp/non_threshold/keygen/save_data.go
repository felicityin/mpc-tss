package keygen

import (
	"encoding/hex"
	"math/big"

	"mpc_tss/crypto"
	"mpc_tss/tss"
)

type (
	LocalKeygenSecrets struct {
		PrivXi, ShareID *big.Int // xi, kj
	}

	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		LocalKeygenSecrets

		// original indexes (ki in signing preparation phase)
		Ks []*big.Int

		// public keys (Xj = uj*G for each Pj)
		PubXj []*crypto.ECPoint // Xj

		// used for assertions and derive child
		Pubkey *crypto.ECPoint // y
	}
)

func NewLocalPartySaveData(partyCount int) (saveData LocalPartySaveData) {
	saveData.Ks = make([]*big.Int, partyCount)
	saveData.PubXj = make([]*crypto.ECPoint, partyCount)
	return
}

// BuildLocalSaveDataSubset re-creates the LocalPartySaveData to contain data for only the list of signing parties.
func BuildLocalSaveDataSubset(sourceData LocalPartySaveData, sortedIDs tss.SortedPartyIDs) LocalPartySaveData {
	keysToIndices := make(map[string]int, len(sourceData.Ks))
	for j, kj := range sourceData.Ks {
		keysToIndices[hex.EncodeToString(kj.Bytes())] = j
	}
	newData := NewLocalPartySaveData(sortedIDs.Len())
	newData.LocalKeygenSecrets = sourceData.LocalKeygenSecrets
	newData.Pubkey = sourceData.Pubkey
	for j, id := range sortedIDs {
		savedIdx, ok := keysToIndices[hex.EncodeToString(id.Key)]
		if !ok {
			panic("BuildLocalSaveDataSubset: unable to find a signer party in the local save data")
		}
		newData.Ks[j] = sourceData.Ks[savedIdx]
		newData.PubXj[j] = sourceData.PubXj[savedIdx]
	}
	return newData
}
