package presign

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"runtime"

	"github.com/pkg/errors"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/protocols/cggmp/keygen"
	"github.com/felicityin/mpc-tss/tss"
)

const (
	testNonThresholdFixtureDirFormat = "%s/../../test/_presign_fixtures/non_threshold"
	testThresholdFixtureDirFormat    = "%s/../../test/_presign_fixtures/threshold"
	testEcdsaFixtureFileFormat       = "ecdsa_presign_data_%d.json"
	testEddsaFixtureFileFormat       = "eddsa_presign_data_%d.json"
)

func LoadAuxTestFixtures(isThreshold bool, kind, qty int, optionalStart ...int) ([]LocalPartySaveData, tss.SortedPartyIDs, error) {
	auxs := make([]LocalPartySaveData, 0, qty)
	start := 0
	if 0 < len(optionalStart) {
		start = optionalStart[0]
	}
	for i := start; i < qty; i++ {
		fixtureFilePath := makeTestFixtureFilePath(isThreshold, kind, i)
		common.Logger.Infof("path: %s", fixtureFilePath)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}
		var aux LocalPartySaveData
		if err = json.Unmarshal(bz, &aux); err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}
		auxs = append(auxs, aux)
	}
	partyIDs := make(tss.UnSortedPartyIDs, len(auxs))
	for i, key := range auxs {
		pMoniker := fmt.Sprintf("%d", i+start+1)
		partyIDs[i] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)
	}
	sortedPIDs := tss.SortPartyIDs(partyIDs)
	return auxs, sortedPIDs, nil
}

func makeTestFixtureFilePath(isThreshold bool, kind, partyIndex int) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)

	var fixtureDirName string
	if isThreshold {
		fixtureDirName = fmt.Sprintf(testThresholdFixtureDirFormat, srcDirName)
	} else {
		fixtureDirName = fmt.Sprintf(testNonThresholdFixtureDirFormat, srcDirName)
	}

	if kind == keygen.Ecdsa {
		return fmt.Sprintf("%s/"+testEcdsaFixtureFileFormat, fixtureDirName, partyIndex)
	}
	return fmt.Sprintf("%s/"+testEddsaFixtureFileFormat, fixtureDirName, partyIndex)
}
