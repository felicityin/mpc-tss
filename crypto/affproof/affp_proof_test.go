package affproof

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAffpProof(test *testing.T) {
	var x, y, rhox, rhoy, rho, C, X, Y, D *big.Int
	x = big.NewInt(3)
	y = big.NewInt(5)
	rhox = big.NewInt(555)
	rhoy = big.NewInt(101)
	rho = big.NewInt(103)
	C = big.NewInt(108)
	X = new(big.Int).Mul(new(big.Int).Exp(new(big.Int).Add(big1, n1), x, n1Square), new(big.Int).Exp(rhox, n1, n1Square))
	Y = new(big.Int).Mul(new(big.Int).Exp(new(big.Int).Add(big1, n1), y, n1Square), new(big.Int).Exp(rhoy, n1, n1Square))
	Y.Mod(Y, n1Square)
	D = new(big.Int).Exp(C, x, n0Square)
	D.Mul(D, new(big.Int).Exp(new(big.Int).Add(big1, n0), y, n0Square))
	D.Mul(D, new(big.Int).Exp(rho, n0, n0Square))
	D.Mod(D, n0Square)
	n0 = new(big.Int).Mul(p0, q0)
	n1 = new(big.Int).Mul(p1, q1)
	pedN = new(big.Int).Mul(pedp, pedq)

	// ok
	zkproof, err := NewPaillierOperationAndPaillierCommitment(config, ssIDInfo, x, y, rho, rhox, rhoy, n0, n1, X, Y, C, D, ped)
	assert.NoError(test, err)
	err = zkproof.Verify(config, ssIDInfo, n0, n1, C, D, X, Y, ped)
	assert.NoError(test, err)

	// wrong config
	config.TwoExpLAddepsilon = big.NewInt(-1)
	zkproof, err = NewPaillierOperationAndPaillierCommitment(config, ssIDInfo, x, y, rho, rhox, rhoy, n0, n1, X, Y, C, D, ped)
	assert.Error(test, err)
	assert.Empty(test, zkproof)
}
