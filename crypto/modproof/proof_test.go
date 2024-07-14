// Copyright © 2022 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package modproof

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	p0, _    = new(big.Int).SetString("104975615121222854384410219330480259027041155688835759631647658735069527864919393410352284436544267374160206678331198777612866309766581999589789442827625308608614590850591998897357449886061863686453412019330757447743487422636807387508460941025550338019105820406950462187693188000168607236389735877001362796259", 10)
	q0, _    = new(big.Int).SetString("102755306389915984635356782597494195047102560555160692696207839728487252530690043689166546890155633162017964085393843240989395317546293846694693801865924045225783240995686020308553449158438908412088178393717793204697268707791329981413862246773904710409946848630083569401668855899757371993960961231481357354607", 10)
	n0       = new(big.Int).Mul(p0, q0)
	ssIDInfo = []byte("Mark HaHa")
)

func TestModProof(test *testing.T) {
	// ok
	zkproof, err := NewPaillierBlumMessage(ssIDInfo, p0, q0, n0, MINIMALCHALLENGE)
	assert.NoError(test, err)
	err = zkproof.Verify(ssIDInfo, n0)
	assert.NoError(test, err)

	// wrong p and q
	zkproof, err = NewPaillierBlumMessage(ssIDInfo, big0, big0, n0, MINIMALCHALLENGE)
	assert.Error(test, err)
	assert.Empty(test, zkproof)
}
