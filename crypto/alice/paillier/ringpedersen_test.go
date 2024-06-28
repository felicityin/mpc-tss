package paillier

import (
	"testing"

	paillierzkproof "mpc_tss/crypto/alice/zkproof/paillier"

	"github.com/stretchr/testify/assert"
)

func TestPaillierZkProof(t *testing.T) {
	ssIDInfo := []byte("Mark HaHa")

	paillierKey, err := NewPaillierSafePrime(2048)
	assert.NoError(t, err)
	ped, err := paillierKey.NewPedersenParameterByPaillier()
	assert.NoError(t, err)

	zkproof, err := paillierzkproof.NewRingPederssenParameterMessage(
		ssIDInfo,
		ped.GetEulerValue(),
		ped.PedersenOpenParameter.GetN(),
		ped.PedersenOpenParameter.GetS(),
		ped.PedersenOpenParameter.GetT(),
		ped.Getlambda(),
		80,
	)

	assert.NoError(t, err)
	err = zkproof.Verify(ssIDInfo)
	assert.NoError(t, err)
}
