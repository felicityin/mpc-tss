package auxiliary

import (
	"encoding/hex"
	"math/big"

	"mpc_tss/common"
	zkPaillier "mpc_tss/crypto/alice/zkproof/paillier"
	"mpc_tss/crypto/paillier"
	"mpc_tss/tss"
)

type (
	LocalSecrets struct {
		PaillierSK *paillier.PrivateKey
	}

	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		LocalSecrets

		ShareID *big.Int

		// original indexes (ki in signing preparation phase)
		Ks []*big.Int

		PaillierPKs []*paillier.PublicKey
		PedersenPKs []*zkPaillier.PederssenOpenParameter
	}
)

func NewLocalPartySaveData(partyCount int) (saveData LocalPartySaveData) {
	saveData.Ks = make([]*big.Int, partyCount)
	saveData.PaillierPKs = make([]*paillier.PublicKey, partyCount)
	saveData.PedersenPKs = make([]*zkPaillier.PederssenOpenParameter, partyCount)
	return
}

// BuildLocalSaveDataSubset re-creates the LocalPartySaveData to contain data for only the list of signing parties.
func BuildLocalSaveDataSubset(sourceData LocalPartySaveData, sortedIDs tss.SortedPartyIDs) LocalPartySaveData {
	keysToIndices := make(map[string]int, len(sourceData.Ks))
	for j, kj := range sourceData.Ks {
		keysToIndices[hex.EncodeToString(kj.Bytes())] = j
	}
	newData := NewLocalPartySaveData(sortedIDs.Len())
	for j, id := range sortedIDs {
		savedIdx, ok := keysToIndices[hex.EncodeToString(id.Key)]
		if !ok {
			common.Logger.Errorf("BuildLocalSaveDataSubset: unable to find a signer party in the local save data: %s", hex.EncodeToString(id.Key))
		}
		newData.Ks[j] = sourceData.Ks[savedIdx]
		newData.PaillierPKs[j] = sourceData.PaillierPKs[savedIdx]
		newData.PedersenPKs[j] = sourceData.PedersenPKs[savedIdx]
	}
	return newData
}
