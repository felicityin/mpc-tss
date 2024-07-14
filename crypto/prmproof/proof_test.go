package prmproof

import (
	"testing"

	"github.com/felicityin/mpc-tss/crypto/alice/paillier"

	"github.com/stretchr/testify/assert"
)

func TestPaillierZkProof(t *testing.T) {
	ssIDInfo := []byte("Mark HaHa")

	paillierKey, err := paillier.NewPaillierSafePrime(2048)
	assert.NoError(t, err)
	ped, err := paillierKey.NewPedersenParameterByPaillier()
	assert.NoError(t, err)

	zkproof, err := NewRingPederssenParameterMessage(
		ssIDInfo,
		ped.GetEulerValue(),
		ped.PedersenOpenParameter.GetN(),
		ped.PedersenOpenParameter.GetS(),
		ped.PedersenOpenParameter.GetT(),
		ped.Getlambda(),
		MINIMALCHALLENGE,
	)

	assert.NoError(t, err)
	err = zkproof.Verify(ssIDInfo)
	assert.NoError(t, err)
}
