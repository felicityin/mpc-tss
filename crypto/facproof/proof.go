// Copyright © 2022 AMIS Technologies

// Reference https://github.com/getamis/alice/blob/master/crypto/zkproof/paillier/nosmallfactoezkproof.go

package facproof

import (
	"errors"
	"math/big"

	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/crypto/alice/utils"
	zkPaillier "github.com/felicityin/mpc-tss/crypto/alice/zkproof/paillier"
)

var big1 = big.NewInt(1)

var ErrVerifyFailure = errors.New("the verification is failure")

func NewNoSmallFactorMessage(
	config *crypto.ProofConfig,
	ssidInfo,
	rho []byte,
	p *big.Int,
	q *big.Int,
	n *big.Int,
	ped *zkPaillier.PederssenOpenParameter,
) (*NoSmallFactorMessage, error) {
	sqrtN := new(big.Int).Sqrt(n)
	groupOrder := config.CurveN
	twoellAddepsionSqrtN := new(big.Int).Lsh(sqrtN, uint(config.LAddEpsilon))
	pedN := ped.GetN()
	peds := ped.GetS()
	pedt := ped.GetT()
	// Sample α,β in ±2^{l+ε}·N0^1/2
	alpha, err := utils.RandomAbsoluteRangeInt(twoellAddepsionSqrtN)
	if err != nil {
		return nil, err
	}
	beta, err := utils.RandomAbsoluteRangeInt(twoellAddepsionSqrtN)
	if err != nil {
		return nil, err
	}
	twoellpedn := new(big.Int).Mul(config.TwoExpL, pedN)
	// Sample μ,ν in ±2^l·N0·Nˆ
	mu, err := utils.RandomAbsoluteRangeInt(twoellpedn)
	if err != nil {
		return nil, err
	}
	v, err := utils.RandomAbsoluteRangeInt(twoellpedn)
	if err != nil {
		return nil, err
	}
	// Sample ρ in ±2^l ·N0 ·Nˆ
	sigma, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(twoellpedn, n))
	if err != nil {
		return nil, err
	}
	twoellAddepsionpedn := new(big.Int).Mul(config.TwoExpLAddepsilon, pedN)
	// Sample r in ±2^{l+ε} ·N0 ·Nˆ
	r, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(twoellAddepsionpedn, n))
	if err != nil {
		return nil, err
	}
	// Sample x, y in ±2^{l+ε} ·N0 ·Nˆ
	x, err := utils.RandomAbsoluteRangeInt(twoellAddepsionpedn)
	if err != nil {
		return nil, err
	}
	y, err := utils.RandomAbsoluteRangeInt(twoellAddepsionpedn)
	if err != nil {
		return nil, err
	}
	// P = s^p*t^μ,Q=s^q*t^ν mod Nˆ.
	P := new(big.Int).Mul(new(big.Int).Exp(peds, p, pedN), new(big.Int).Exp(pedt, mu, pedN))
	P.Mod(P, pedN)
	Q := new(big.Int).Mul(new(big.Int).Exp(peds, q, pedN), new(big.Int).Exp(pedt, v, pedN))
	Q.Mod(Q, pedN)
	// A=s^α*t^x mod Nˆ.
	A := new(big.Int).Mul(new(big.Int).Exp(peds, alpha, pedN), new(big.Int).Exp(pedt, x, pedN))
	A.Mod(A, pedN)
	// B=s^β*t^y mod Nˆ.
	B := new(big.Int).Mul(new(big.Int).Exp(peds, beta, pedN), new(big.Int).Exp(pedt, y, pedN))
	B.Mod(B, pedN)
	// T = Q^α*t^r mod Nˆ.
	T := new(big.Int).Mul(new(big.Int).Exp(Q, alpha, pedN), new(big.Int).Exp(pedt, r, pedN))
	T.Mod(T, pedN)
	e, salt, err := zkPaillier.GetE(groupOrder, utils.GetAnyMsg(ssidInfo, rho, n.Bytes(), pedN.Bytes(), peds.Bytes(), pedt.Bytes(), P.Bytes(), Q.Bytes(), A.Bytes(), B.Bytes(), T.Bytes(), sigma.Bytes())...)
	if err != nil {
		return nil, err
	}
	// z1 = α + ep, z2 =β+eq, w1 = x+eμ, w2 =y+eν, and v = r+eρ ˆ.
	z1 := new(big.Int).Add(alpha, new(big.Int).Mul(e, p))
	z2 := new(big.Int).Add(beta, new(big.Int).Mul(e, q))
	w1 := new(big.Int).Add(x, new(big.Int).Mul(e, mu))
	w2 := new(big.Int).Add(y, new(big.Int).Mul(e, v))
	vletter := new(big.Int).Add(r, new(big.Int).Mul(e, new(big.Int).Sub(sigma, new(big.Int).Mul(v, p))))

	return &NoSmallFactorMessage{
		Salt:    salt,
		P:       P.Bytes(),
		Q:       Q.Bytes(),
		A:       A.Bytes(),
		B:       B.Bytes(),
		T:       T.Bytes(),
		Sigma:   sigma.String(),
		Z1:      z1.String(),
		Z2:      z2.String(),
		W1:      w1.String(),
		W2:      w2.String(),
		Vletter: vletter.String(),
	}, nil
}

func (msg *NoSmallFactorMessage) Verify(config *crypto.ProofConfig, ssidInfo, rho []byte, n *big.Int, ped *zkPaillier.PederssenOpenParameter) error {
	groupOrder := config.CurveN
	pedN := ped.GetN()
	peds := ped.GetS()
	pedt := ped.GetT()
	P := new(big.Int).SetBytes(msg.P)
	Q := new(big.Int).SetBytes(msg.Q)
	A := new(big.Int).SetBytes(msg.A)
	B := new(big.Int).SetBytes(msg.B)
	T := new(big.Int).SetBytes(msg.T)
	sigma, _ := new(big.Int).SetString(msg.Sigma, 10)
	z1, _ := new(big.Int).SetString(msg.Z1, 10)
	z2, _ := new(big.Int).SetString(msg.Z2, 10)
	w1, _ := new(big.Int).SetString(msg.W1, 10)
	w2, _ := new(big.Int).SetString(msg.W2, 10)
	v, _ := new(big.Int).SetString(msg.Vletter, 10)

	R := new(big.Int).Mul(new(big.Int).Exp(peds, n, pedN), new(big.Int).Exp(pedt, sigma, pedN))
	R.Mod(R, pedN)

	seed, err := utils.HashProtos(msg.Salt, utils.GetAnyMsg(ssidInfo, rho, n.Bytes(), pedN.Bytes(), peds.Bytes(), pedt.Bytes(), P.Bytes(), Q.Bytes(), A.Bytes(), B.Bytes(), T.Bytes(), sigma.Bytes())...)
	if err != nil {
		return err
	}

	e := utils.RandomAbsoluteRangeIntBySeed(msg.Salt, seed, groupOrder)
	err = utils.InRange(e, new(big.Int).Neg(groupOrder), new(big.Int).Add(big1, groupOrder))
	if err != nil {
		return err
	}
	// Check z1, z2 in ±N0^1/2*2^{l+ε}.
	sqrtN := new(big.Int).Sqrt(n)
	absZ1 := new(big.Int).Abs(z1)
	upBd := new(big.Int).Lsh(sqrtN, uint(config.LAddEpsilon))
	if absZ1.Cmp(upBd) > 0 {
		return ErrVerifyFailure
	}
	absZ2 := new(big.Int).Abs(z2)
	if absZ2.Cmp(upBd) > 0 {
		return ErrVerifyFailure
	}
	// Set R = s^{N0}*t^ρ. Check s^{z1}*t^{w1} = A·P^e mod Nˆ.
	ADexpe := new(big.Int).Mul(A, new(big.Int).Exp(P, e, pedN))
	ADexpe.Mod(ADexpe, pedN)
	compare := new(big.Int).Mul(new(big.Int).Exp(peds, z1, pedN), new(big.Int).Exp(pedt, w1, pedN))
	compare.Mod(compare, pedN)
	if compare.Cmp(ADexpe) != 0 {
		return ErrVerifyFailure
	}
	// Check s^{z2}t^{w2} =B·Q^e mod Nˆ.
	BQexpe := new(big.Int).Mul(B, new(big.Int).Exp(Q, e, pedN))
	BQexpe.Mod(BQexpe, pedN)
	compare = new(big.Int).Mul(new(big.Int).Exp(peds, z2, pedN), new(big.Int).Exp(pedt, w2, pedN))
	compare.Mod(compare, pedN)
	if compare.Cmp(BQexpe) != 0 {
		return ErrVerifyFailure
	}
	// Check Q^{z1}t^v =T·R^e mod Nˆ.
	TRexpe := new(big.Int).Mul(T, new(big.Int).Exp(R, e, pedN))
	TRexpe.Mod(TRexpe, pedN)
	compare = new(big.Int).Mul(new(big.Int).Exp(Q, z1, pedN), new(big.Int).Exp(pedt, v, pedN))
	compare.Mod(compare, pedN)
	if compare.Cmp(TRexpe) != 0 {
		return ErrVerifyFailure
	}
	return nil
}
