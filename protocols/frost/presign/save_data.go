package presign

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/tss"
)

type (
	LocalSecrets struct {
		ShareID *big.Int
		D       *big.Int
		E       *big.Int
	}

	DE struct {
		D *crypto.ECPoint
		E *crypto.ECPoint
	}

	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		LocalSecrets

		DEs []*DE

		// original indexes (ki in signing preparation phase)
		Ks []*big.Int
	}
)

func NewLocalPartySaveData(partyCount int) (saveData LocalPartySaveData) {
	saveData.Ks = make([]*big.Int, partyCount)
	saveData.DEs = make([]*DE, partyCount)
	return
}

// recovers a party's original index in the set of parties during keygen
func (save LocalPartySaveData) OriginalIndex() (int, error) {
	index := -1
	ki := save.ShareID
	for j, kj := range save.Ks {
		if kj.Cmp(ki) != 0 {
			continue
		}
		index = j
		break
	}
	if index < 0 {
		return -1, errors.New("a party index could not be recovered from Ks")
	}
	return index, nil
}

// BuildLocalSaveDataSubset re-creates the LocalPartySaveData to contain data for only the list of signing parties.
func BuildLocalSaveDataSubset(sourceData LocalPartySaveData, sortedIDs tss.SortedPartyIDs) (newData LocalPartySaveData, err error) {
	keysToIndices := make(map[string]int, len(sourceData.Ks))
	for j, kj := range sourceData.Ks {
		keysToIndices[hex.EncodeToString(kj.Bytes())] = j
	}
	newData = NewLocalPartySaveData(sortedIDs.Len())
	newData.LocalSecrets = sourceData.LocalSecrets
	for j, id := range sortedIDs {
		savedIdx, ok := keysToIndices[hex.EncodeToString(id.Key)]
		if !ok {
			common.Logger.Errorf("unable to find a signer party in the presign local save data: %s", hex.EncodeToString(id.Key))
			err = fmt.Errorf("unable to find a signer party in the presign local save data: %s", hex.EncodeToString(id.Key))
			return
		}
		newData.Ks[j] = sourceData.Ks[savedIdx]
		newData.DEs[j] = sourceData.DEs[savedIdx]
	}
	return newData, nil
}
