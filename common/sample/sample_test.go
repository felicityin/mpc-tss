package sample

import (
	"crypto/rand"
	"math/big"
	"testing"

	"mpc_tss/common/pool"
)

const blumPrimeProbabilityIterations = 20

func TestPaillier(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	pNat, _ := Paillier(rand.Reader, pl)
	p := pNat
	if !p.ProbablyPrime(blumPrimeProbabilityIterations) {
		t.Error("BlumPrime generated a non prime number: ", p)
	}
	q := new(big.Int).Sub(p, new(big.Int).SetUint64(1))
	q.Rsh(q, 1)
	if !q.ProbablyPrime(blumPrimeProbabilityIterations) {
		t.Error("p isn't safe because (p - 1) / 2 isn't prime", q)
	}
}

// This exists to save the results of functions we want to benchmark, to avoid
// having them optimized away.
var resultNat *big.Int

func BenchmarkPaillier(b *testing.B) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	for i := 0; i < b.N; i++ {
		resultNat, _ = Paillier(rand.Reader, pl)
	}
}
