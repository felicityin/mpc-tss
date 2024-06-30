// Reference github.com/getamis/alice/crypto/homo/paillier/paillier.go

package paillier

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/felicityin/mpc-tss/crypto/alice/utils"
	"github.com/felicityin/mpc-tss/crypto/alice/zkproof"

	"github.com/golang/protobuf/proto"
)

const (
	// safePubKeySize is the permitted lowest size of Public Key.
	safePubKeySize = 2048

	// maxGenN defines the max retries to generate N
	maxGenN = 100
	// maxGenG defines the max retries to generate G
	maxGenG = 100
	// maxRetry defines the max retries
	maxRetry = 100
)

var (
	//ErrExceedMaxRetry is returned if we retried over times
	ErrExceedMaxRetry = errors.New("exceed max retries")
	//ErrInvalidInput is returned if the input is invalid
	ErrInvalidInput = errors.New("invalid input")
	//ErrInvalidMessage is returned if the message is invalid
	ErrInvalidMessage = errors.New("invalid message")
	//ErrSmallPublicKeySize is returned if the size of public key is small
	ErrSmallPublicKeySize = errors.New("small public key")

	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)
)

// PublicKey is (n, g)
type PublicKey struct {
	N *big.Int
	G *big.Int

	Msg *PubKeyMessage

	// cache value
	NSquare *big.Int
}

func (pub *PublicKey) GetMessageRange(fieldOrder *big.Int) *big.Int {
	rangeK := computeStatisticalClosedRange(fieldOrder)
	return new(big.Int).Sub(pub.N, rangeK)
}

func (pub *PublicKey) GetNSquare() *big.Int {
	return new(big.Int).Set(pub.NSquare)
}

func (pub *PublicKey) GetN() *big.Int {
	return new(big.Int).Set(pub.N)
}

func (pub *PublicKey) GetG() *big.Int {
	return new(big.Int).Set(pub.G)
}

func (pub *PublicKey) Encrypt(mBytes []byte) ([]byte, error) {
	m := new(big.Int).SetBytes(mBytes)
	// Ensure 0 <= m < n
	if m.Cmp(pub.N) >= 0 {
		return nil, ErrInvalidMessage
	}
	c, _, err := pub.EncryptWithOutputSalt(m)
	if err != nil {
		return nil, err
	}
	//c.Mod(c, pub.nSquare)
	return c.Bytes(), nil
}

func (pub *PublicKey) EncryptWithOutputSalt(m *big.Int) (*big.Int, *big.Int, error) {
	// gcd(r, n)=1
	r, err := utils.RandomCoprimeInt(pub.N)
	if err != nil {
		return nil, nil, err
	}

	// c = (g^m * r^n) mod n^2
	gm := new(big.Int).Exp(pub.G, m, pub.NSquare) // g^m
	rn := new(big.Int).Exp(r, pub.N, pub.NSquare) // r^n
	c := new(big.Int).Mul(gm, rn)
	c = c.Mod(c, pub.NSquare)
	return c, r, nil
}

// In paillier, we cannot verify enc message. Therefore, we always return nil.
func (pub *PublicKey) VerifyEnc([]byte) error {
	return nil
}

// Refer: https://en.wikipedia.org/wiki/Paillier_cryptosystem
// PrivateKey is (λ, μ)
type PrivateKey struct {
	P      *big.Int
	Q      *big.Int
	Lambda *big.Int // λ=lcm(p−1, q−1)
	PhiN   *big.Int // (p-1) * (q-1)
	Mu     *big.Int // μ=(L(g^λ mod n^2))^-1 mod n
}

type Paillier struct {
	*PublicKey
	PrivateKey *PrivateKey
}

func (p *Paillier) GetPubN() *big.Int {
	return new(big.Int).Set(p.N)
}

func (p *Paillier) GetPubG() *big.Int {
	return new(big.Int).Set(p.G)
}

func (p *Paillier) GetPrivP() *big.Int {
	return new(big.Int).Set(p.PrivateKey.P)
}

func (p *Paillier) GetPrivQ() *big.Int {
	return new(big.Int).Set(p.PrivateKey.Q)
}

func (p *Paillier) GetPrivLambda() *big.Int {
	return new(big.Int).Set(p.PrivateKey.Lambda)
}

func (p *Paillier) GetPrivPhiN() *big.Int {
	return new(big.Int).Set(p.PrivateKey.PhiN)
}

func (p *Paillier) GetPrivMu() *big.Int {
	return new(big.Int).Set(p.PrivateKey.Mu)
}

func NewPaillier(keySize int) (*Paillier, error) {
	if keySize < safePubKeySize {
		return nil, ErrSmallPublicKeySize
	}
	return NewPaillierUnSafe(keySize, false)
}

func NewPaillierSafePrime(keySize int) (*Paillier, error) {
	if keySize < safePubKeySize {
		return nil, ErrSmallPublicKeySize
	}
	return NewPaillierUnSafe(keySize, true)
}

// Warning: No check the size of public key.
func NewPaillierUnSafe(keySize int, isSafe bool) (*Paillier, error) {
	p, q, n, lambda, phiN, err := getNAndLambda(keySize, isSafe)
	if err != nil {
		return nil, err
	}
	g, mu, err := getGAndMuWithSpecialG(lambda, n)
	if err != nil {
		return nil, err
	}
	msg, err := zkproof.NewIntegerFactorizationProofMessage([]*big.Int{p, q}, n)
	if err != nil {
		return nil, err
	}
	pubKeyMessage := &PubKeyMessage{
		Proof: msg,
		G:     g.Bytes(),
	}
	pub, err := pubKeyMessage.ToPubkey()
	if err != nil {
		return nil, err
	}
	return &Paillier{
		PublicKey: pub,
		PrivateKey: &PrivateKey{
			P:      p,
			Q:      q,
			Lambda: lambda,
			PhiN:   phiN,
			Mu:     mu,
		},
	}, nil
}

// Decrypt computes the plaintext from the ciphertext
func (p *Paillier) Decrypt(cBytes []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(cBytes)
	pub := p.PublicKey
	priv := p.PrivateKey

	err := isCorrectCiphertext(c, pub)
	if err != nil {
		return nil, err
	}

	x := new(big.Int).Exp(c, priv.Lambda, pub.NSquare)
	l, err := lFunction(x, pub.N)
	if err != nil {
		return nil, err
	}
	l = l.Mul(l, priv.Mu)
	l = l.Mod(l, pub.N)
	return l.Bytes(), nil
}

// getNAndLambda returns N and lambda.
// n = pq and lambda = lcm(p-1, q-1)
// phiN = (p-1)(q-1)
func getNAndLambda(keySize int, isSafe bool) (*big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
	pqSize := keySize / 2
	for i := 0; i < maxGenN; i++ {
		p, q, err := generatePrime(isSafe, pqSize)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		pMinus1 := new(big.Int).Sub(p, big1)    // p-1
		qMinus1 := new(big.Int).Sub(q, big1)    // q-1
		n := new(big.Int).Mul(p, q)             // n=p*q
		m := new(big.Int).Mul(pMinus1, qMinus1) // m=(p-1)*(q-1)
		// gcd(pq, (p-1)(q-1)) = 1
		if utils.IsRelativePrime(n, m) {
			lambda, err := utils.Lcm(pMinus1, qMinus1)
			if err == nil {
				return p, q, n, lambda, m, err
			}
		}
	}
	return nil, nil, nil, nil, nil, ErrExceedMaxRetry
}

func generatePrime(isSafe bool, primeSize int) (*big.Int, *big.Int, error) {
	if isSafe {
		for i := 0; i < maxRetry; i++ {
			safeP, err := utils.GenerateRandomSafePrime(rand.Reader, primeSize)
			if err != nil {
				return nil, nil, err
			}
			safeQ, err := utils.GenerateRandomSafePrime(rand.Reader, primeSize)
			if err != nil {
				return nil, nil, err
			}
			p := new(big.Int).Set(safeP.P)
			q := new(big.Int).Set(safeQ.P)

			// Because the bit length of p and q are the same and p!= q, GCD(p, q)=1.
			if p.Cmp(q) == 0 {
				continue
			}
			return p, q, nil
		}
		return nil, nil, ErrExceedMaxRetry
	}
	for i := 0; i < maxRetry; i++ {
		p, err := rand.Prime(rand.Reader, primeSize)
		if err != nil {
			return nil, nil, err
		}
		q, err := rand.Prime(rand.Reader, primeSize)
		if err != nil {
			return nil, nil, err
		}

		// Because the bit length of p and q are the same and p!= q, GCD(p, q)=1.
		if p.Cmp(q) == 0 {
			continue
		}
		return p, q, nil
	}
	return nil, nil, ErrExceedMaxRetry
}

func isCorrectCiphertext(c *big.Int, pubKey *PublicKey) error {
	// Ensure 0 < c < n^2
	err := utils.InRange(c, big1, pubKey.NSquare)
	if err != nil {
		return err
	}
	// c and n should be relative prime
	if !utils.IsRelativePrime(c, pubKey.N) {
		return ErrInvalidMessage
	}
	return nil
}

// getGAndMu returns G and mu.
func getGAndMuWithSpecialG(lambda *big.Int, n *big.Int) (*big.Int, *big.Int, error) {
	nSquare := new(big.Int).Mul(n, n) // n^2
	for i := 0; i < maxGenG; i++ {
		g := new(big.Int).Add(big1, n)            // g
		x := new(big.Int).Exp(g, lambda, nSquare) // x
		u, err := lFunction(x, n)
		if err != nil {
			return nil, nil, err
		}

		mu := new(big.Int).ModInverse(u, n)
		// if mu is nil, it means u and n are not relatively prime. We need to try again
		if mu == nil {
			continue
		}
		return g, mu, nil
	}
	return nil, nil, ErrExceedMaxRetry
}

// lFunction computes L(x)=(x-1)/n
func lFunction(x, n *big.Int) (*big.Int, error) {
	if n.Cmp(big0) <= 0 {
		return nil, ErrInvalidInput
	}
	if x.Cmp(big0) <= 0 {
		return nil, ErrInvalidInput
	}
	t := new(big.Int).Sub(x, big1)
	t = t.Div(t, n)
	return t, nil
}

/*
1. Check that c1, c2 is correct.
2. Choose (r, N)=1 with r in [1, N-1] randomly.
3. Compute c1*c2*r^N mod N^2.
*/
func (pub *PublicKey) Add(c1Bytes []byte, c2Bytes []byte) ([]byte, error) {
	c1 := new(big.Int).SetBytes(c1Bytes)
	c2 := new(big.Int).SetBytes(c2Bytes)
	err := isCorrectCiphertext(c1, pub)
	if err != nil {
		return nil, err
	}
	err = isCorrectCiphertext(c2, pub)
	if err != nil {
		return nil, err
	}

	result := new(big.Int).Mul(c1, c2)
	result = result.Mod(result, pub.NSquare)

	r, err := utils.RandomCoprimeInt(pub.N)
	if err != nil {
		return nil, err
	}
	rn := new(big.Int).Exp(r, pub.N, pub.NSquare)
	result = result.Mul(result, rn)
	result = result.Mod(result, pub.NSquare)
	return result.Bytes(), nil
}

/*
1. Check that c is correct.
2. Compute scalar mod N.
3. Choose (r, N)=1 with r in [1, N-1] randomly.
4. Compute c^scalar*r^N mod N^2.
*/
func (pub *PublicKey) MulConst(cBytes []byte, scalar *big.Int) ([]byte, error) {
	c := new(big.Int).SetBytes(cBytes)
	err := isCorrectCiphertext(c, pub)
	if err != nil {
		return nil, err
	}
	scalarModN := new(big.Int).Mod(scalar, pub.N)
	result := new(big.Int).Exp(c, scalarModN, pub.NSquare)
	r, err := utils.RandomCoprimeInt(pub.N)
	if err != nil {
		return nil, err
	}
	rn := new(big.Int).Exp(r, pub.N, pub.NSquare)
	result = result.Mul(result, rn)
	result = result.Mod(result, pub.NSquare)
	return result.Bytes(), nil
}

func (pub *PublicKey) ToPubKeyBytes() []byte {
	// We can ignore this error, because the resulting message is produced by ourself.
	bs, _ := proto.Marshal(pub.Msg)
	return bs
}

func computeStatisticalClosedRange(n *big.Int) *big.Int {
	nMinus := new(big.Int).Sub(n, big1)
	nMinusSquare := new(big.Int).Exp(nMinus, big2, nil)
	return nMinusSquare
}

func (p *Paillier) GetNthRoot() (*big.Int, error) {
	eulerValue, err := utils.EulerFunction([]*big.Int{p.PrivateKey.P, p.PrivateKey.Q})
	if err != nil {
		return nil, err
	}
	return new(big.Int).ModInverse(p.N, eulerValue), nil
}
