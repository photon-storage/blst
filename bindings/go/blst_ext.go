package blst

// #cgo CFLAGS: -I${SRCDIR}/.. -I${SRCDIR}/../../build -I${SRCDIR}/../../src -D__BLST_CGO__ -fno-builtin-memcpy -fno-builtin-memset
// #cgo amd64 CFLAGS: -D__ADX__ -mno-avx
// #cgo mips64 mips64le ppc64 ppc64le riscv64 s390x CFLAGS: -D__BLST_NO_ASM__
// #include "blst.h"
import "C"

// P2Mult implements a "sign" function that multiplies a point
// on G2 with the given scalar to get another point on G2.
func P2Mult(q *P2, s *Scalar) *P2Affine {
	sig := new(P2Affine)
	C.blst_sign_pk2_in_g1(nil, sig, q, s)
	return sig
}

// Build reduced scalar from arbitrary input value.
func ScalarFromBytes(arr []byte) *Scalar {
	s := new(Scalar)
	nbytes := len(arr)
	C.blst_scalar_from_be_bytes(s, (*C.byte)(&arr[0]), C.size_t(nbytes))
	return s
}
