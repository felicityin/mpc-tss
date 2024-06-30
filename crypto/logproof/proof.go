// Copyright © 2022 AMIS Technologies

// Reference https://github.com/getamis/alice/blob/master/crypto/zkproof/paillier/logstar.go

package logproof

import (
	"fmt"
	"math/big"

	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/crypto/alice/utils"
	zKpaillier "github.com/felicityin/mpc-tss/crypto/alice/zkproof/paillier"

	errors2 "github.com/pkg/errors"
)

var (
	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)

	ErrVerifyFailure = "the logproof verification is failure"
)

// Common input is (G, q, N0, C, X, g).
// The Prover has secret input (x, ρ) such that x ∈ ±2^l,
// and C = (1 + N0)^x · ρ^N0 mod N0^2 and X = g^x ∈ G
func NewKnowExponentAndPaillierEncryption(
	config *crypto.ProofConfig,
	ssidInfo []byte,
	x, rho, C, N0 *big.Int,
	ped *zKpaillier.PederssenOpenParameter,
	X *crypto.ECPoint,
	G *crypto.ECPoint,
) (*LogStarMessage, error) {
	if G == nil {
		var err error
		if G, err = crypto.NewECPoint(X.Curve(), X.Curve().Params().Gx, X.Curve().Params().Gy); err != nil {
			return nil, fmt.Errorf("calc base point err: %s", err.Error())
		}
	}

	n0Square := new(big.Int).Exp(N0, big2, nil)
	curveN := config.CurveN
	pedN := ped.N
	peds := ped.S
	pedt := ped.T
	// Sample α in ± 2^{l+ε}.
	alpha, err := utils.RandomAbsoluteRangeInt(config.TwoExpLAddepsilon)
	if err != nil {
		return nil, err
	}
	// Sample μ in ± 2^{l+ε}·Nˆ.
	mu, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(config.TwoExpL, pedN))
	if err != nil {
		return nil, err
	}
	// Sample r in Z_{N0}^ast
	r, err := utils.RandomCoprimeInt(N0)
	if err != nil {
		return nil, err
	}
	// Sample γ in ± 2^{l+ε}·Nˆ
	gamma, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(config.TwoExpLAddepsilon, pedN))
	if err != nil {
		return nil, err
	}
	// S = s^x*t^μ mod Nˆ
	S := new(big.Int).Mul(new(big.Int).Exp(peds, x, pedN), new(big.Int).Exp(pedt, mu, pedN))
	S.Mod(S, pedN)
	// A = (1+N_0)^α ·r^{N_0} mod N_0^2
	A := new(big.Int).Mul(new(big.Int).Exp(new(big.Int).Add(big1, N0), alpha, n0Square), new(big.Int).Exp(r, N0, n0Square))
	A.Mod(A, n0Square)
	// Y := α*G
	Y := G.ScalarMult(alpha)
	// D = s^α*t^γ
	D := new(big.Int).Mul(new(big.Int).Exp(peds, alpha, pedN), new(big.Int).Exp(pedt, gamma, pedN))
	D.Mod(D, pedN)

	msgs := utils.GetAnyMsg(ssidInfo, new(big.Int).SetUint64(config.LAddEpsilon).Bytes(),
		N0.Bytes(), pedN.Bytes(), C.Bytes(), S.Bytes(), A.Bytes(), D.Bytes(), G.Y().Bytes(), X.Y().Bytes(), Y.Y().Bytes())
	e, salt, err := zKpaillier.GetE(curveN, msgs...)
	if err != nil {
		return nil, err
	}

	// z1 = α+ex
	z1 := new(big.Int).Add(alpha, new(big.Int).Mul(e, x))
	// z2 = r·ρ^e mod N_0
	z2 := new(big.Int).Mul(r, new(big.Int).Exp(rho, e, N0))
	z2.Mod(z2, N0)
	// z3 = γ+eμ
	z3 := new(big.Int).Add(gamma, new(big.Int).Mul(e, mu))

	return &LogStarMessage{
		Salt: salt,
		S:    S.Bytes(),
		A:    A.Bytes(),
		Yx:   Y.X().Bytes(),
		Yy:   Y.Y().Bytes(),
		D:    D.Bytes(),
		Z1:   z1.String(),
		Z2:   z2.Bytes(),
		Z3:   z3.String(),
	}, nil
}

func (msg *LogStarMessage) Verify(
	config *crypto.ProofConfig,
	ssidInfo []byte,
	C, N0 *big.Int,
	ped *zKpaillier.PederssenOpenParameter,
	X *crypto.ECPoint,
	G *crypto.ECPoint,
) error {
	if G == nil {
		var err error
		if G, err = crypto.NewECPoint(X.Curve(), X.Curve().Params().Gx, X.Curve().Params().Gy); err != nil {
			return fmt.Errorf("calc base point err: %s", err.Error())
		}
	}

	n0Square := new(big.Int).Exp(N0, big2, nil)
	curveN := config.CurveN
	pedN := ped.N
	peds := ped.S
	pedt := ped.T
	// check A in Z_{N0^2}^\ast, S,D in Z_{\hat{N}}^\ast, and z2 in Z_{0}^\ast.
	S := new(big.Int).SetBytes(msg.S)
	err := utils.InRange(S, big0, pedN)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(S, pedN) {
		return errors2.Errorf("%s: !utils.IsRelativePrime(S, pedN)", ErrVerifyFailure)
	}
	A := new(big.Int).SetBytes(msg.A)
	err = utils.InRange(A, big0, n0Square)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(A, N0) {
		return errors2.Errorf("%s: !utils.IsRelativePrime(A, n0)", ErrVerifyFailure)
	}
	D := new(big.Int).SetBytes(msg.D)
	err = utils.InRange(D, big0, pedN)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(D, pedN) {
		return errors2.Errorf("%s: !utils.IsRelativePrime(D, pedN)", ErrVerifyFailure)
	}
	z1, _ := new(big.Int).SetString(msg.Z1, 10)
	z2 := new(big.Int).SetBytes(msg.Z2)
	err = utils.InRange(z2, big0, N0)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(z2, N0) {
		return errors2.Errorf("%s: !utils.IsRelativePrime(z2, n0)", ErrVerifyFailure)
	}
	z3, _ := new(big.Int).SetString(msg.Z3, 10)

	Y, err := crypto.NewECPoint(G.Curve(), new(big.Int).SetBytes(msg.GetYx()), new(big.Int).SetBytes(msg.GetYy()))
	if err != nil {
		return err
	}

	msgs := utils.GetAnyMsg(ssidInfo, new(big.Int).SetUint64(config.LAddEpsilon).Bytes(),
		N0.Bytes(), pedN.Bytes(), C.Bytes(), S.Bytes(), A.Bytes(), D.Bytes(), G.Y().Bytes(), X.Y().Bytes(), Y.Y().Bytes())
	seed, err := utils.HashProtos(msg.Salt, msgs...)
	if err != nil {
		return err
	}

	e := utils.RandomAbsoluteRangeIntBySeed(msg.Salt, seed, curveN)
	err = utils.InRange(e, new(big.Int).Neg(curveN), new(big.Int).Add(big1, curveN))
	if err != nil {
		return err
	}

	// Check z_1 in ±2^{l+ε}.
	absZ1 := new(big.Int).Abs(z1)
	if absZ1.Cmp(new(big.Int).Lsh(big2, uint(config.LAddEpsilon))) > 0 {
		return errors2.Errorf("%s: absZ1.Cmp(new(big.Int).Lsh(big2, uint(config.LAddEpsilon))) > 0", ErrVerifyFailure)
	}
	// Check z1*G =Y + e*X
	YXexpe := X.ScalarMult(e)
	YXexpe, err = YXexpe.Add(Y)
	if err != nil {
		return err
	}
	gz1 := G.ScalarMult(z1)
	if !(gz1.X().Cmp(YXexpe.X()) == 0 && gz1.Y().Cmp(YXexpe.Y()) == 0) {
		return errors2.Errorf("%s: !(gz1.X().Cmp(YXexpe.X()) == 0 && gz1.Y().Cmp(YXexpe.Y()) == 0)", ErrVerifyFailure)
	}
	// Check (1+N_0)^{z1}z2^{N_0} = A·C^e mod N_0^2.
	AKexpe := new(big.Int).Mul(A, new(big.Int).Exp(C, e, n0Square))
	AKexpe.Mod(AKexpe, n0Square)
	compare := new(big.Int).Exp(z2, N0, n0Square)
	compare.Mul(compare, new(big.Int).Exp(new(big.Int).Add(big1, N0), z1, n0Square))
	compare.Mod(compare, n0Square)
	if compare.Cmp(AKexpe) != 0 {
		return errors2.Errorf("%s: compare.Cmp(AKexpe) != 0", ErrVerifyFailure)
	}
	// Check s^{z1}t^{z3} =E·S^e mod Nˆ
	sz1tz3 := new(big.Int).Mul(new(big.Int).Exp(peds, z1, pedN), new(big.Int).Exp(pedt, z3, pedN))
	sz1tz3.Mod(sz1tz3, pedN)
	DSexpe := new(big.Int).Mul(D, new(big.Int).Exp(S, e, pedN))
	DSexpe.Mod(DSexpe, pedN)
	if sz1tz3.Cmp(DSexpe) != 0 {
		return errors2.Errorf("%s: sz1tz3.Cmp(DSexpe) != 0", ErrVerifyFailure)
	}
	return nil
}
