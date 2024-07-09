package presign

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"runtime"

	"github.com/pkg/errors"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/tss"
)

const (
	testNonThresholdFixtureDirFormat = "%s/../../test/_presign_fixtures/non_threshold"
	testThresholdFixtureDirFormat    = "%s/../../test/_presign_fixtures/threshold"
	testFixtureFileFormat            = "eddsa_presign_data_%d.json"
)

func LoadPreTestFixtures(isThreshold bool, qty int, optionalStart ...int) ([]LocalPartySaveData, tss.SortedPartyIDs, error) {
	pres := make([]LocalPartySaveData, 0, qty)
	start := 0
	if 0 < len(optionalStart) {
		start = optionalStart[0]
	}
	for i := start; i < qty; i++ {
		fixtureFilePath := makeTestFixtureFilePath(isThreshold, i)
		common.Logger.Infof("path: %s", fixtureFilePath)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}
		var pre LocalPartySaveData
		if err = json.Unmarshal(bz, &pre); err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}
		pres = append(pres, pre)
	}
	partyIDs := make(tss.UnSortedPartyIDs, len(pres))
	for i, key := range pres {
		pMoniker := fmt.Sprintf("%d", i+start+1)
		partyIDs[i] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)
	}
	sortedPIDs := tss.SortPartyIDs(partyIDs)
	return pres, sortedPIDs, nil
}

func makeTestFixtureFilePath(isThreshold bool, partyIndex int) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)

	var fixtureDirName string
	if isThreshold {
		fixtureDirName = fmt.Sprintf(testThresholdFixtureDirFormat, srcDirName)
	} else {
		fixtureDirName = fmt.Sprintf(testNonThresholdFixtureDirFormat, srcDirName)
	}

	return fmt.Sprintf("%s/"+testFixtureFileFormat, fixtureDirName, partyIndex)
}
