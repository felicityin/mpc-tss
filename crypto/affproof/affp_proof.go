// Copyright © 2022 AMIS Technologies

// Reference https://github.com/getamis/alice/blob/master/crypto/zkproof/paillier/operation_commitment.go

package affproof

import (
	"math/big"

	"mpc_tss/crypto"
	"mpc_tss/crypto/alice/utils"
	zkPaillier "mpc_tss/crypto/alice/zkproof/paillier"
)

func NewPaillierOperationAndPaillierCommitment(
	config *crypto.ProofConfig,
	ssidInfo []byte,
	x, y, rho, rhox, rhoy, n0, n1, X, Y, C, D *big.Int,
	ped *zkPaillier.PederssenOpenParameter,
) (*PaillierOperationAndCommitmentMessage, error) {
	n0Square := new(big.Int).Exp(n0, big2, nil)
	n1Square := new(big.Int).Exp(n1, big2, nil)
	fieldOrder := config.CurveN
	pedN := ped.GetN()
	peds := ped.GetS()
	pedt := ped.GetT()
	// Sample α in ± 2^{l+ε}, β in ±2^{l'+ε}.
	alpha, err := utils.RandomAbsoluteRangeInt(config.TwoExpLAddepsilon)
	if err != nil {
		return nil, err
	}
	beta, err := utils.RandomAbsoluteRangeInt(config.TwoExpLpaiAddepsilon)
	if err != nil {
		return nil, err
	}
	// Sample r in Z_{N0}^ast, rx in Z_{N1}^ast and ry in Z_{N1}^ast
	r, err := utils.RandomCoprimeInt(n0)
	if err != nil {
		return nil, err
	}
	rx, err := utils.RandomCoprimeInt(n1)
	if err != nil {
		return nil, err
	}
	ry, err := utils.RandomCoprimeInt(n1)
	if err != nil {
		return nil, err
	}
	// Sample γ in ± 2^{l+ε}·Nˆ and m in ±2^l ·Nˆ
	gamma, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(config.TwoExpLAddepsilon, pedN))
	if err != nil {
		return nil, err
	}
	m, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(config.TwoExpL, pedN))
	if err != nil {
		return nil, err
	}
	// δ in ± 2^{l+ε}·Nˆ and μ in ± 2^{l+ε}·Nˆ
	delta, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(config.TwoExpLAddepsilon, pedN))
	if err != nil {
		return nil, err
	}
	mu, err := utils.RandomAbsoluteRangeInt(new(big.Int).Mul(config.TwoExpL, pedN))
	if err != nil {
		return nil, err
	}
	// A=C^α·((1+N_0)^β·r^N0) mod N0^2
	A := new(big.Int).Mul(new(big.Int).Exp(C, alpha, n0Square), new(big.Int).Exp(r, n0, n0Square))
	A.Mul(A, new(big.Int).Exp(new(big.Int).Add(big1, n0), beta, n0Square))
	A.Mod(A, n0Square)
	// B_x = (1+N_1)^α ·rx^{N_1} mod N_1^2
	Bx := new(big.Int).Exp(rx, n1, n1Square)
	Bx.Mul(Bx, new(big.Int).Exp(new(big.Int).Add(big1, n1), alpha, n1Square))
	Bx.Mod(Bx, n1Square)
	// B_y = (1+N_1)^α ·ry^{N_1} mod N_1^2
	By := new(big.Int).Mul(new(big.Int).Exp(new(big.Int).Add(big1, n1), beta, n1Square), new(big.Int).Exp(ry, n1, n1Square))
	By.Mod(By, n1Square)
	// E = s^α*t^γ mod Nˆ and S = s^x*t^m mod Nˆ
	E := new(big.Int).Mul(new(big.Int).Exp(peds, alpha, pedN), new(big.Int).Exp(pedt, gamma, pedN))
	E.Mod(E, pedN)
	S := new(big.Int).Mul(new(big.Int).Exp(peds, x, pedN), new(big.Int).Exp(pedt, m, pedN))
	S.Mod(S, pedN)
	// F = s^β*t^δ mod Nˆ and T = s^y*t^μ mod Nˆ
	F := new(big.Int).Mul(new(big.Int).Exp(peds, beta, pedN), new(big.Int).Exp(pedt, delta, pedN))
	F.Mod(F, pedN)
	T := new(big.Int).Mul(new(big.Int).Exp(peds, y, pedN), new(big.Int).Exp(pedt, mu, pedN))
	T.Mod(T, pedN)

	e, salt, err := zkPaillier.GetE(
		fieldOrder, utils.GetAnyMsg(ssidInfo, new(big.Int).SetUint64(config.LAddEpsilon).Bytes(),
			new(big.Int).SetUint64(config.LpaiAddEpsilon).Bytes(), n0.Bytes(), n1.Bytes(), C.Bytes(),
			D.Bytes(), X.Bytes(), Y.Bytes(), S.Bytes(), T.Bytes(), A.Bytes(), Bx.Bytes(), By.Bytes(), E.Bytes(), F.Bytes())...,
	)
	if err != nil {
		return nil, err
	}
	// z1 = α + ex, z2 =β+ey, z3 = γ + em, z4 =δ+eμ, w = r · ρ^e mod N_0, wx = rx · ρx^e and wy = ry · ρy^e mod N1.
	z1 := new(big.Int).Add(alpha, new(big.Int).Mul(e, x))
	z2 := new(big.Int).Add(beta, new(big.Int).Mul(e, y))
	z3 := new(big.Int).Add(gamma, new(big.Int).Mul(e, m))
	z4 := new(big.Int).Add(delta, new(big.Int).Mul(e, mu))
	w := new(big.Int).Mul(r, new(big.Int).Exp(rho, e, n0))
	w.Mod(w, n0)
	wx := new(big.Int).Mul(rx, new(big.Int).Exp(rhox, e, n1))
	wx.Mod(wx, n1)
	wy := new(big.Int).Mul(ry, new(big.Int).Exp(rhoy, e, n1))
	wy.Mod(wy, n1)

	return &PaillierOperationAndCommitmentMessage{
		Salt: salt,
		S:    S.Bytes(),
		T:    T.Bytes(),
		A:    A.Bytes(),
		Bx:   Bx.Bytes(),
		By:   By.Bytes(),
		E:    E.Bytes(),
		F:    F.Bytes(),
		Z1:   z1.String(),
		Z2:   z2.String(),
		Z3:   z3.String(),
		Z4:   z4.String(),
		W:    w.Bytes(),
		Wx:   wx.Bytes(),
		Wy:   wy.Bytes(),
	}, nil
}

func (msg *PaillierOperationAndCommitmentMessage) Verify(
	config *crypto.ProofConfig,
	ssidInfo []byte,
	n0, n1, C, D, X, Y *big.Int,
	ped *zkPaillier.PederssenOpenParameter,
) error {
	n0Square := new(big.Int).Exp(n0, big2, nil)
	n1Square := new(big.Int).Exp(n1, big2, nil)
	fieldOrder := config.CurveN
	pedN := ped.GetN()
	peds := ped.GetS()
	pedt := ped.GetT()
	// check A in Z_{N0^2}^\ast, By, Bx in Z_{N1^2}^\ast, E,S,T,F in Z_{\hat{N}}^\ast, w in Z_{N0}^\ast, and wx, wy in Z_{N1}^\ast.
	S := new(big.Int).SetBytes(msg.S)
	err := utils.InRange(S, big0, pedN)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(S, pedN) {
		return ErrVerifyFailure
	}
	T := new(big.Int).SetBytes(msg.T)
	err = utils.InRange(T, big0, pedN)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(T, pedN) {
		return ErrVerifyFailure
	}
	A := new(big.Int).SetBytes(msg.A)
	err = utils.InRange(A, big0, n0Square)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(A, n0Square) {
		return ErrVerifyFailure
	}
	By := new(big.Int).SetBytes(msg.By)
	err = utils.InRange(By, big0, n1Square)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(By, n1Square) {
		return ErrVerifyFailure
	}
	E := new(big.Int).SetBytes(msg.E)
	err = utils.InRange(E, big0, pedN)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(E, pedN) {
		return ErrVerifyFailure
	}
	F := new(big.Int).SetBytes(msg.F)
	err = utils.InRange(F, big0, pedN)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(F, pedN) {
		return ErrVerifyFailure
	}
	z1, _ := new(big.Int).SetString(msg.Z1, 10)
	z2, _ := new(big.Int).SetString(msg.Z2, 10)
	z3, _ := new(big.Int).SetString(msg.Z3, 10)
	z4, _ := new(big.Int).SetString(msg.Z4, 10)
	W := new(big.Int).SetBytes(msg.W)
	err = utils.InRange(W, big0, n0)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(W, n0) {
		return ErrVerifyFailure
	}
	Wy := new(big.Int).SetBytes(msg.Wy)
	err = utils.InRange(Wy, big0, n1)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(Wy, n1) {
		return ErrVerifyFailure
	}
	Bx := new(big.Int).SetBytes(msg.Bx)
	err = utils.InRange(Bx, big0, n1Square)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(Bx, n1Square) {
		return ErrVerifyFailure
	}
	Wx := new(big.Int).SetBytes(msg.Wx)
	err = utils.InRange(Wx, big0, n1)
	if err != nil {
		return err
	}
	if !utils.IsRelativePrime(Wx, n1) {
		return ErrVerifyFailure
	}

	seed, err := utils.HashProtos(
		msg.Salt, utils.GetAnyMsg(ssidInfo, new(big.Int).SetUint64(config.LAddEpsilon).Bytes(),
			new(big.Int).SetUint64(config.LpaiAddEpsilon).Bytes(), n0.Bytes(), n1.Bytes(), C.Bytes(),
			D.Bytes(), X.Bytes(), Y.Bytes(), S.Bytes(), T.Bytes(), A.Bytes(), Bx.Bytes(), By.Bytes(), E.Bytes(), F.Bytes())...,
	)
	if err != nil {
		return err
	}
	e := utils.RandomAbsoluteRangeIntBySeed(msg.Salt, seed, fieldOrder)
	err = utils.InRange(e, new(big.Int).Neg(fieldOrder), new(big.Int).Add(big1, fieldOrder))
	if err != nil {
		return err
	}
	// Check z_1 in ±2^{l+ε}.
	absZ1 := new(big.Int).Abs(z1)
	if absZ1.Cmp(new(big.Int).Lsh(big2, uint(config.LAddEpsilon))) > 0 {
		return ErrVerifyFailure
	}
	// Check z_2 in ±2^{l′+ε}.
	absZ2 := new(big.Int).Abs(z2)
	if absZ2.Cmp(new(big.Int).Lsh(big2, uint(config.LpaiAddEpsilon))) > 0 {
		return ErrVerifyFailure
	}
	// Check C^{z1}(1+N_0)^{z2}w^{N_0} = A·D^e mod N_0^2.
	ADexpe := new(big.Int).Mul(A, new(big.Int).Exp(D, e, n0Square))
	ADexpe.Mod(ADexpe, n0Square)
	compare := new(big.Int).Exp(C, z1, n0Square)
	compare.Mul(compare, new(big.Int).Exp(new(big.Int).Add(big1, n0), z2, n0Square))
	compare.Mul(compare, new(big.Int).Exp(W, n0, n0Square))
	compare.Mod(compare, n0Square)
	if compare.Cmp(ADexpe) != 0 {
		return ErrVerifyFailure
	}
	// Check (1+N_1)^{z_1}wx^{N_1} = B_x·X^e mod N_1^2.
	BxXexpe := new(big.Int).Mul(Bx, new(big.Int).Exp(X, e, n1Square))
	BxXexpe.Mod(BxXexpe, n1Square)
	compare = new(big.Int).Exp(Wx, n1, n1Square)
	compare.Mul(compare, new(big.Int).Exp(new(big.Int).Add(big1, n1), z1, n1Square))
	compare.Mod(compare, n1Square)
	if compare.Cmp(BxXexpe) != 0 {
		return ErrVerifyFailure
	}
	// Check (1+N_1)^{z_2}wy^{N_1} = B_y·Y^e mod N_1^2.
	Byyexpe := new(big.Int).Mul(By, new(big.Int).Exp(Y, e, n1Square))
	Byyexpe.Mod(Byyexpe, n1Square)
	compare = new(big.Int).Exp(Wy, n1, n1Square)
	compare.Mul(compare, new(big.Int).Exp(new(big.Int).Add(big1, n1), z2, n1Square))
	compare.Mod(compare, n1Square)
	if compare.Cmp(Byyexpe) != 0 {
		return ErrVerifyFailure
	}
	// Check s^{z1}t^{z3} =E·S^e mod Nˆ
	sz1tz3 := new(big.Int).Mul(new(big.Int).Exp(peds, z1, pedN), new(big.Int).Exp(pedt, z3, pedN))
	sz1tz3.Mod(sz1tz3, pedN)
	ESexpe := new(big.Int).Mul(E, new(big.Int).Exp(S, e, pedN))
	ESexpe.Mod(ESexpe, pedN)
	if sz1tz3.Cmp(ESexpe) != 0 {
		return ErrVerifyFailure
	}
	// Check s^{z2}t^{z4} =F·T^e mod Nˆ
	sz2tz4 := new(big.Int).Mul(new(big.Int).Exp(peds, z2, pedN), new(big.Int).Exp(pedt, z4, pedN))
	sz2tz4.Mod(sz2tz4, pedN)
	FTexpe := new(big.Int).Mul(F, new(big.Int).Exp(T, e, pedN))
	FTexpe.Mod(FTexpe, pedN)
	if FTexpe.Cmp(sz2tz4) != 0 {
		return ErrVerifyFailure
	}
	return nil
}
