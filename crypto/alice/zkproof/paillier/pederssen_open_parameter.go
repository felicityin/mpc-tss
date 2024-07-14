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

package paillier

import (
	"math/big"
)

type PederssenOpenParameter struct {
	N *big.Int
	S *big.Int
	T *big.Int
}

func NewPedersenOpenParameter(n, s, t *big.Int) *PederssenOpenParameter {
	return &PederssenOpenParameter{
		N: n,
		S: s,
		T: t,
	}
}

func (ped *PederssenOpenParameter) GetN() *big.Int {
	return ped.N
}

func (ped *PederssenOpenParameter) GetS() *big.Int {
	return ped.S
}

func (ped *PederssenOpenParameter) GetT() *big.Int {
	return ped.T
}
