// Copyright © 2022 AMIS Technologies

package crypto

import "math/big"

var (
	big2 = big.NewInt(2)
)

const (
	LFactor       = 1
	LpaiFactor    = 5
	epsilonFactor = 2
)

type ProofConfig struct {
	CurveN               *big.Int
	TwoExpLAddepsilon    *big.Int
	TwoExpLpaiAddepsilon *big.Int
	TwoExpL              *big.Int
	LAddEpsilon          uint64
	LpaiAddEpsilon       uint64
	Lpai                 uint
}

func NewProofConfig(curveN *big.Int) *ProofConfig {
	epsilon := uint(epsilonFactor * curveN.BitLen())
	L := uint(LFactor * curveN.BitLen())
	Lpai := uint(LpaiFactor * curveN.BitLen())
	return &ProofConfig{
		CurveN:               curveN,
		TwoExpLAddepsilon:    new(big.Int).Lsh(big2, L+epsilon),
		TwoExpLpaiAddepsilon: new(big.Int).Lsh(big2, Lpai+epsilon),
		TwoExpL:              new(big.Int).Lsh(big2, L),
		LAddEpsilon:          uint64(L + epsilon),
		LpaiAddEpsilon:       uint64(Lpai + epsilon),
		Lpai:                 Lpai,
	}
}
