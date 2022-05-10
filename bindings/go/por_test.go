package blst_test

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	blst "github.com/photon-storage/blst/bindings/go"
)

// Demonstration of PoR construction using blst primitives.

var dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POR_")

var BLS12_381_r = func() *big.Int {
	data, _ := hex.DecodeString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
	return new(big.Int).SetBytes(data)
}()

func value32(t *testing.T) *big.Int {
	var v [32]byte
	_, err := rand.Read(v[:])
	if err != nil {
		t.Error(err)
	}
	return new(big.Int).SetBytes(v[:])
}

func reduce(v *big.Int) *blst.Scalar {
	return blst.ScalarFromBytes(new(big.Int).Mod(v, BLS12_381_r).Bytes())
}

func scalar(t *testing.T) *blst.Scalar {
	return blst.ScalarFromBytes(value32(t).Bytes())
}

func genKeys(t *testing.T) (*blst.SecretKey, *blst.P1Affine) {
	var ikm [32]byte
	_, err := rand.Read(ikm[:])
	if err != nil {
		t.Error(err)
	}
	sk := blst.KeyGen(ikm[:])
	pk := new(blst.P1Affine).From(sk)
	return sk, pk
}

func toP2(aff *blst.P2Affine) *blst.P2 {
	p2 := new(blst.P2)
	p2.FromAffine(aff)
	return p2
}

func TestScalarMultOnce(t *testing.T) {
	sk, pk := genKeys(t)
	u := blst.HashToG2([]byte("u"), dst)
	// sig = u^sk
	sig := blst.P2Mult(u, sk)

	// e(u^sk, g1) = e(u, pk)
	a := blst.Fp12MillerLoop(sig, blst.P1Generator().ToAffine())
	b := blst.Fp12MillerLoop(u.ToAffine(), pk)
	if !blst.Fp12FinalVerify(a, b) {
		t.Error("pairing verification failure")
	}
}

func TestScalarMultTwice(t *testing.T) {
	sk, pk := genKeys(t)
	u := blst.HashToG2([]byte("u"), dst)
	v := scalar(t)
	// sig = u^sk
	sig := blst.P2Mult(u, sk)
	// sigma = u^(sk+v)
	sigma := blst.P2Mult(toP2(sig), v)

	// e(u^(sk+v), g1) = e(u^v, pk)
	a := blst.Fp12MillerLoop(sigma, blst.P1Generator().ToAffine())
	b := blst.Fp12MillerLoop(blst.P2Mult(u, v), pk)
	if !blst.Fp12FinalVerify(a, b) {
		t.Error("pairing verification failure")
	}
}

func TestScalarMultTwiceSum(t *testing.T) {
	sk, pk := genKeys(t)
	u0 := blst.HashToG2([]byte("u0"), dst)
	u1 := blst.HashToG2([]byte("u1"), dst)
	v0 := scalar(t)
	v1 := scalar(t)
	// sig = u^sk
	sig0 := blst.P2Mult(u0, sk)
	sig1 := blst.P2Mult(u1, sk)
	// sigma = u^(sk+v)
	sigma0 := blst.P2Mult(toP2(sig0), v0)
	sigma1 := blst.P2Mult(toP2(sig1), v1)
	// sigma = sigma0 * sigma1
	sigma := blst.P2AffinesAdd([]*blst.P2Affine{
		sigma0,
		sigma1,
	})
	// sum = u0^v0 * u1^v1
	sum := blst.P2AffinesAdd([]*blst.P2Affine{
		blst.P2Mult(u0, v0),
		blst.P2Mult(u1, v1),
	})

	// e(u0^(sk+v0) * u1^(sk+v1), g1) = e(u0^v0 * u1^v1, pk)
	a := blst.Fp12MillerLoop(sigma.ToAffine(), blst.P1Generator().ToAffine())
	b := blst.Fp12MillerLoop(sum.ToAffine(), pk)
	if !blst.Fp12FinalVerify(a, b) {
		t.Error("pairing verification failure")
	}
}

func TestScalarAdd(t *testing.T) {
	u := blst.HashToG2([]byte("u"), dst)
	a := value32(t)
	b := value32(t)
	sum := new(big.Int).Add(a, b)

	// expected = u^a * u^b
	expected := blst.P2AffinesAdd([]*blst.P2Affine{
		blst.P2Mult(u, reduce(a)),
		blst.P2Mult(u, reduce(b)),
	}).ToAffine()
	// got = u^(a+b)
	got := blst.P2Mult(u, reduce(sum))
	if !expected.Equals(got) {
		t.Error("scalar addition failure")
	}
}

func TestPoRConstruction(t *testing.T) {
	sk, pk := genKeys(t)

	// File chunks:
	// 2 blocks,
	// 3 sectors per block
	// 32 bytes per sector
	m00 := scalar(t)
	m01 := scalar(t)
	m02 := scalar(t)
	m10 := scalar(t)
	m11 := scalar(t)
	m12 := scalar(t)

	// Random elements from G2, one per sector.
	u0 := blst.HashToG2([]byte("u0"), dst)
	u1 := blst.HashToG2([]byte("u1"), dst)
	u2 := blst.HashToG2([]byte("u2"), dst)

	// Block signatures
	// sigma[i] = H(i) * u0^m[i,0] * u1^m[i,1] * u2^m[i,2]
	sigma0 := blst.P2Mult(
		blst.P2AffinesAdd([]*blst.P2Affine{
			blst.HashToG2([]byte("block0"), dst).ToAffine(),
			blst.P2Mult(u0, m00),
			blst.P2Mult(u1, m01),
			blst.P2Mult(u2, m02),
		}),
		sk,
	)
	sigma1 := blst.P2Mult(
		blst.P2AffinesAdd([]*blst.P2Affine{
			blst.HashToG2([]byte("block1"), dst).ToAffine(),
			blst.P2Mult(u0, m10),
			blst.P2Mult(u1, m11),
			blst.P2Mult(u2, m12),
		}),
		sk,
	)

	// Random elements selected for challenge
	// One per challenged block.
	v0 := scalar(t)
	v1 := scalar(t)

	// Proofs: one per sector
	// mu[j] = v0*m[0,j] + v1*m[1,j]
	// proof[j] = u0^mu0 = u0^(v0*m[0,j]) * u0^(v1*m[1,j])
	proof0 := blst.P2AffinesAdd([]*blst.P2Affine{
		blst.P2Mult(toP2(blst.P2Mult(u0, v0)), m00),
		blst.P2Mult(toP2(blst.P2Mult(u0, v1)), m10),
	})
	proof1 := blst.P2AffinesAdd([]*blst.P2Affine{
		blst.P2Mult(toP2(blst.P2Mult(u1, v0)), m01),
		blst.P2Mult(toP2(blst.P2Mult(u1, v1)), m11),
	})
	proof2 := blst.P2AffinesAdd([]*blst.P2Affine{
		blst.P2Mult(toP2(blst.P2Mult(u2, v0)), m02),
		blst.P2Mult(toP2(blst.P2Mult(u2, v1)), m12),
	})

	// sigma = sigma0^v0 * sigma1^v1
	sigma := blst.P2AffinesAdd([]*blst.P2Affine{
		blst.P2Mult(toP2(sigma0), v0),
		blst.P2Mult(toP2(sigma1), v1),
	})

	// e(sigma0^v0 * sigma1^v1, g1) = e(H(0) * H(1) * proof0 * proof1 * proof2, pk)
	a := blst.Fp12MillerLoop(sigma.ToAffine(), blst.P1Generator().ToAffine())
	b := blst.Fp12MillerLoop(blst.P2AffinesAdd([]*blst.P2Affine{
		blst.P2Mult(blst.HashToG2([]byte("block0"), dst), v0),
		blst.P2Mult(blst.HashToG2([]byte("block1"), dst), v1),
		proof0.ToAffine(),
		proof1.ToAffine(),
		proof2.ToAffine(),
	}).ToAffine(), pk)
	if !blst.Fp12FinalVerify(a, b) {
		t.Error("pairing verification failure")
	}
}

func TestPorWithPublicVerification(t *testing.T) {
	sk, pk := genKeys(t)

	// File chunks:
	// 2 blocks,
	// 3 sectors per block
	m00 := value32(t)
	m01 := value32(t)
	m02 := value32(t)
	m10 := value32(t)
	m11 := value32(t)
	m12 := value32(t)

	// Random elements from G2, one per sector.
	u0 := blst.HashToG2([]byte("u0"), dst)
	u1 := blst.HashToG2([]byte("u1"), dst)
	u2 := blst.HashToG2([]byte("u2"), dst)

	// Block signatures
	// sigma[i] = H(i) * u0^m[i,0] * u1^m[i,1] * u2^m[i,2]
	sigma0 := blst.P2Mult(
		blst.P2AffinesAdd([]*blst.P2Affine{
			blst.HashToG2([]byte("block0"), dst).ToAffine(),
			blst.P2Mult(u0, reduce(m00)),
			blst.P2Mult(u1, reduce(m01)),
			blst.P2Mult(u2, reduce(m02)),
		}),
		sk,
	)
	sigma1 := blst.P2Mult(
		blst.P2AffinesAdd([]*blst.P2Affine{
			blst.HashToG2([]byte("block1"), dst).ToAffine(),
			blst.P2Mult(u0, reduce(m10)),
			blst.P2Mult(u1, reduce(m11)),
			blst.P2Mult(u2, reduce(m12)),
		}),
		sk,
	)

	// Random elements selected for challenge
	// One per challenged block.
	v0 := value32(t)
	v1 := value32(t)

	// Scalar dot-product calculated by proofer.
	mu0 := new(big.Int).Add(
		new(big.Int).Mul(v0, m00),
		new(big.Int).Mul(v1, m10),
	)
	mu1 := new(big.Int).Add(
		new(big.Int).Mul(v0, m01),
		new(big.Int).Mul(v1, m11),
	)
	mu2 := new(big.Int).Add(
		new(big.Int).Mul(v0, m02),
		new(big.Int).Mul(v1, m12),
	)

	// sigma = sigma0^v0 * sigma1^v1
	sigma := blst.P2AffinesAdd([]*blst.P2Affine{
		blst.P2Mult(toP2(sigma0), reduce(v0)),
		blst.P2Mult(toP2(sigma1), reduce(v1)),
	})

	// e(sigma0^v0 * sigma1^v1, g1) = e(H(0) * H(1) * u0^mu0 * u1^mu1 * u2^mu2, pk)
	a := blst.Fp12MillerLoop(sigma.ToAffine(), blst.P1Generator().ToAffine())
	b := blst.Fp12MillerLoop(blst.P2AffinesAdd([]*blst.P2Affine{
		blst.P2Mult(blst.HashToG2([]byte("block0"), dst), reduce(v0)),
		blst.P2Mult(blst.HashToG2([]byte("block1"), dst), reduce(v1)),
		blst.P2Mult(u0, reduce(mu0)),
		blst.P2Mult(u1, reduce(mu1)),
		blst.P2Mult(u2, reduce(mu2)),
	}).ToAffine(), pk)
	if !blst.Fp12FinalVerify(a, b) {
		t.Error("pairing verification failure")
	}
}
