// Code generated from mode3/internal/dilithium.go by gen.go

package internal

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/internal/sha3"
	common "github.com/cloudflare/circl/sign/internal/dilithium"
)

const (
	// Size of a packed polynomial of norm ≤η.
	// (Note that the  formula is not valid in general.)
	PolyLeqEtaSize = (common.N * DoubleEtaBits) / 8

	// β = τη, the maximum size of c s₂.
	Beta = Tau * Eta

	// γ₁ range of y
	Gamma1 = 1 << Gamma1Bits

	// Size of packed polynomial of norm <γ₁ such as z
	PolyLeGamma1Size = (Gamma1Bits + 1) * common.N / 8

	// α = 2γ₂ parameter for decompose
	Alpha = 2 * Gamma2

	// Size of a packed public key
	PublicKeySize = 32 + common.PolyT1Size*K

	// Size of a packed signature
	SignatureSize = L*PolyLeGamma1Size + Omega + K + CTildeSize

	// Size of packed w₁
	PolyW1Size = (common.N * (common.QBits - Gamma1Bits)) / 8

	// [THRESHOLD]
	// Size of packed w
	PolyQSize = (common.N * common.QBits) / 8

	// Size of a packed commitment
	SingleCommitmentSize = K * PolyQSize

	// Size of a packed response
	SingleResponseSize = L * PolyLeGamma1Size
)

// PublicKey is the type of Dilithium public keys.
type PublicKey struct {
	rho [32]byte
	t1  VecK

	// Cached values
	t1p [common.PolyT1Size * K]byte
	A   *Mat
	Tr  *[TRSize]byte
}

// PrivateKey is the type of Dilithium private keys.
type Share struct {
	s1 VecL
	s2 VecK

	// Cached values
	s1h VecL // NTT(s₁)
	s2h VecK // NTT(s₂)
}

// PrivateKey is the type of Dilithium private keys.
type PrivateKey struct {
	Id uint8

	rho [32]byte
	key [32]byte
	s1  VecL
	s2  VecK
	Tr  [TRSize]byte

	shares map[uint8]*Share

	// Cached values
	A   Mat  // ExpandA(ρ)
	s1h VecL // NTT(s₁)
	s2h VecK // NTT(s₂)
}

// ThresholdParams contains parameters for threshold ML-DSA-65
type ThresholdParams struct {
	// T is the threshold - minimum number of parties needed to sign
	T uint8
	// N is the total number of parties
	N uint8
	// K is the number of iterations for the threshold protocol
	K uint16
	// Nu is the increase factor for the threshold version
	nu float64
	// R is the primary radius parameter
	r float64
	// RPrime is the secondary radius parameter
	rPrime float64
}

func (params *ThresholdParams) PrivateKeySize() int {
	sharesPerParty := binomial(params.N-1, params.T-1)
	return 1 + 32 + 32 + TRSize + (1+PolyLeqEtaSize*(L+K))*sharesPerParty
}

func defaultThresholdParams() *ThresholdParams {
	return &ThresholdParams{
		T:      1,
		N:      1,
		K:      1,
		nu:     1,
		r:      221116.151669661,
		rPrime: 221041.3274003604,
	}
}

// GetThresholdParams returns recommended parameters for threshold ML-DSA-65
// given threshold T and total number of parties N.
// Returns error if parameters are invalid.
func GetThresholdParams(t, n uint8) (*ThresholdParams, error) {
	// Validate parameters
	if t < 2 {
		return nil, errors.New("threshold T must be 2 or more")
	}
	if t > n {
		return nil, errors.New("threshold T must be less than or equal to total parties N")
	}
	if n > 6 {
		return nil, errors.New("number of parties must be less than 6")
	}

	var k uint16
	var r, rPrime float64
	nu := float64(6.)
	if t == 2 && n == 2 { // N = 2
		k = uint16(3)   // Number of iterations
		r = 501495      // Primary radius
		rPrime = 501613 // Secondary radius
	} else if n == 3 { // N = 3
		ks := []uint16{5, 9}
		rs := []float64{540212, 540378}
		rPs := []float64{510387, 510504}
		k = ks[t-2]
		r = rs[t-2]
		rPrime = rPs[t-2]
	} else if n == 4 { // N = 3
		ks := []uint16{6, 20, 26}
		rs := []float64{540212, 506761, 433594}
		rPs := []float64{540378, 506928, 433711}
		k = ks[t-2]
		r = rs[t-2]
		rPrime = rPs[t-2]
	} else if n == 5 { // N = 3
		ks := []uint16{8, 62, 205, 78}
		rs := []float64{552371, 552909, 474331, 425914}
		rPs := []float64{552575, 553145, 474535, 426032}
		k = ks[t-2]
		r = rs[t-2]
		rPrime = rPs[t-2]
	} else if n == 6 { // N = 3
		ks := []uint16{8, 95, 804, 1200, 250}
		rs := []float64{571208, 536793, 488704, 461324, 414896}
		rPs := []float64{571412, 537058, 488969, 461529, 415013}
		k = ks[t-2]
		r = rs[t-2]
		rPrime = rPs[t-2]
	} else {
		panic("not supported")
	}

	return &ThresholdParams{
		T:      t,
		N:      n,
		K:      k,
		nu:     nu,
		r:      r,
		rPrime: rPrime,
	}, nil
}

// PrivateKey is the type of Dilithium private keys.
type ThCommitmentRand FVec

type unpackedSignature struct {
	z    VecL
	hint VecK
	c    [CTildeSize]byte
}

// Packs the signature into buf.
func (sig *unpackedSignature) Pack(buf []byte) {
	copy(buf[:], sig.c[:])
	sig.z.PackLeGamma1(buf[CTildeSize:])
	sig.hint.PackHint(buf[CTildeSize+L*PolyLeGamma1Size:])
}

// Sets sig to the signature encoded in the buffer.
//
// Returns whether buf contains a properly packed signature.
func (sig *unpackedSignature) Unpack(buf []byte) bool {
	if len(buf) < SignatureSize {
		return false
	}
	copy(sig.c[:], buf[:])
	sig.z.UnpackLeGamma1(buf[CTildeSize:])
	if sig.z.Exceeds(Gamma1 - Beta) {
		return false
	}
	if !sig.hint.UnpackHint(buf[CTildeSize+L*PolyLeGamma1Size:]) {
		return false
	}
	return true
}

// Packs the public key into buf.
func (pk *PublicKey) Pack(buf *[PublicKeySize]byte) {
	copy(buf[:32], pk.rho[:])
	copy(buf[32:], pk.t1p[:])
}

// Sets pk to the public key encoded in buf.
func (pk *PublicKey) Unpack(buf *[PublicKeySize]byte) {
	copy(pk.rho[:], buf[:32])
	copy(pk.t1p[:], buf[32:])

	pk.t1.UnpackT1(pk.t1p[:])
	pk.A = new(Mat)
	pk.A.Derive(&pk.rho)

	// tr = CRH(ρ ‖ t1) = CRH(pk)
	pk.Tr = new([TRSize]byte)
	h := sha3.NewShake256()
	_, _ = h.Write(buf[:])
	_, _ = h.Read(pk.Tr[:])
}

// Packs the private key into buf.
func (sk *PrivateKey) Pack(buf []byte) {
	buf[0] = sk.Id
	copy(buf[1:33], sk.rho[:])
	copy(buf[33:65], sk.key[:])
	copy(buf[65:65+TRSize], sk.Tr[:])
	offset := 65 + TRSize
	for index, share := range sk.shares {
		buf[offset] = byte(index)
		offset++
		share.s1.PackLeqEta(buf[offset:])
		offset += PolyLeqEtaSize * L
		share.s2.PackLeqEta(buf[offset:])
		offset += PolyLeqEtaSize * K
	}
}

// Sets sk to the private key encoded in buf.
func (sk *PrivateKey) Unpack(buf []byte) {
	sk.Id = buf[0]
	copy(sk.rho[:], buf[1:33])
	copy(sk.key[:], buf[33:65])
	copy(sk.Tr[:], buf[65:65+TRSize])
	sk.shares = make(map[uint8]*Share)
	offset := 65 + TRSize
	for offset < len(buf) {
		act := buf[offset]
		offset++
		share := Share{}
		share.s1.UnpackLeqEta(buf[offset:])
		offset += PolyLeqEtaSize * L
		share.s2.UnpackLeqEta(buf[offset:])
		offset += PolyLeqEtaSize * K

		share.s1h = share.s1
		share.s1h.NTT()
		share.s2h = share.s2
		share.s2h.NTT()
		sk.shares[act] = &share
	}

	// Cached values
	sk.A.Derive(&sk.rho)
}

// NewKeyFromSeed derives a public/private key pair using the given seed.
func NewThresholdKeysFromSeed(seed *[common.SeedSize]byte, params *ThresholdParams) (*PublicKey, []PrivateKey) {
	fmt.Printf("%s\n", Name)
	var pk PublicKey
	sks := make([]PrivateKey, params.N)

	h := sha3.NewShake256()
	_, _ = h.Write(seed[:])

	if NIST {
		_, _ = h.Write([]byte{byte(K), byte(L)})
	}

	_, _ = h.Read(pk.rho[:])
	pk.A = new(Mat)
	pk.A.Derive(&pk.rho)

	var sktot PrivateKey
	sktot.A = *pk.A

	// Initialize the private keys
	for i := uint8(0); i < params.N; i++ {
		sks[i].Id = i

		_, _ = h.Read(sks[i].key[:])
		copy(sks[i].rho[:], pk.rho[:])
		sks[i].A = *pk.A

		sks[i].shares = make(map[uint8]*Share)
	}

	// Sample the shares
	honestSigners := uint8((1 << (params.N - params.T + 1)) - 1)
	for honestSigners < (1 << params.N) {
		var share Share
		var sSeed [64]byte
		_, _ = h.Read(sSeed[:])

		for j := uint16(0); j < L; j++ {
			PolyDeriveUniformLeqEta(&share.s1[j], &sSeed, j)
		}

		for j := uint16(0); j < K; j++ {
			PolyDeriveUniformLeqEta(&share.s2[j], &sSeed, j+L)
		}

		share.s1h = share.s1
		share.s1h.NTT()
		share.s2h = share.s2
		share.s2h.NTT()

		// Distribute the share
		for i := uint8(0); i < params.N; i++ {
			if (honestSigners & (1 << i)) != 0 {
				sks[i].shares[honestSigners] = &share
			}
		}

		sktot.s1.Add(&sktot.s1, &share.s1)
		sktot.s1h.Add(&sktot.s1h, &share.s1h)
		sktot.s2.Add(&sktot.s2, &share.s2)
		sktot.s2h.Add(&sktot.s2h, &share.s2h)

		// next possible set of honest signers
		c := honestSigners & -honestSigners
		r := honestSigners + c
		honestSigners = (((r ^ honestSigners) >> 2) / c) | r
	}

	sktot.s1.Normalize()
	sktot.s1h.Normalize()
	sktot.s2.Normalize()
	sktot.s2h.Normalize()

	computeT0andT1(pk.A, &sktot.s1h, &sktot.s2, &pk.t1)

	// Complete public key far enough to be packed
	pk.t1.PackT1(pk.t1p[:])

	// Finish private key
	var packedPk [PublicKeySize]byte
	pk.Pack(&packedPk)

	// tr = CRH(ρ ‖ t1) = CRH(pk)
	h.Reset()
	_, _ = h.Write(packedPk[:])
	_, _ = h.Read(sktot.Tr[:])

	// Finish cache of public key
	pk.Tr = &sktot.Tr

	for i := uint8(0); i < params.N; i++ {
		sks[i].Tr = sktot.Tr
	}

	return &pk, sks
}

// binomial calculates n choose k
func binomial(n, k uint8) int {
	if k > n {
		return 0
	}
	if k == 0 || k == n {
		return 1
	}
	k = min(k, n-k)
	c := 1
	for i := uint8(0); i < k; i++ {
		c = c * (int(n) - int(i)) / (int(i) + 1)
	}
	return c
}

// Computes t0 and t1 from s1h, s2 and A.
func computeT0andT1(A *Mat, s1h *VecL, s2, t1 *VecK) {
	var t0, t VecK

	// Set t to A s₁ + s₂
	for i := 0; i < K; i++ {
		PolyDotHat(&t[i], &A[i], s1h)
		t[i].ReduceLe2Q()
		t[i].InvNTT()
	}
	t.Add(&t, s2)
	t.Normalize()

	// Compute t₀, t₁ = Power2Round(t)
	t.Power2Round(&t0, t1)
}

// Verify checks whether the given signature by pk on msg is valid.
//
// For Dilithium this is the top-level verification function.
// In ML-DSA, this is ML-DSA.Verify_internal.
func Verify(pk *PublicKey, msg func(io.Writer), signature []byte) bool {
	var sig unpackedSignature
	var mu [64]byte
	var zh VecL
	var Az, Az2dct1, w1 VecK
	var ch common.Poly
	var cp [CTildeSize]byte
	var w1Packed [PolyW1Size * K]byte

	// Note that Unpack() checked whether ‖z‖_∞ < γ₁ - β
	// and ensured that there at most ω ones in pk.hint.
	if !sig.Unpack(signature) {
		return false
	}

	// μ = CRH(tr ‖ msg)
	h := sha3.NewShake256()
	_, _ = h.Write(pk.Tr[:])
	msg(&h)
	_, _ = h.Read(mu[:])

	// Compute Az
	zh = sig.z
	zh.NTT()

	for i := 0; i < K; i++ {
		PolyDotHat(&Az[i], &pk.A[i], &zh)
	}

	// Next, we compute Az - 2ᵈ·c·t₁.
	// Note that the coefficients of t₁ are bounded by 256 = 2⁹,
	// so the coefficients of Az2dct1 will bounded by 2⁹⁺ᵈ = 2²³ < 2q,
	// which is small enough for NTT().
	Az2dct1.MulBy2toD(&pk.t1)
	Az2dct1.NTT()
	PolyDeriveUniformBall(&ch, sig.c[:])
	ch.NTT()
	for i := 0; i < K; i++ {
		Az2dct1[i].MulHat(&Az2dct1[i], &ch)
	}
	Az2dct1.Sub(&Az, &Az2dct1)
	Az2dct1.ReduceLe2Q()
	Az2dct1.InvNTT()
	Az2dct1.NormalizeAssumingLe2Q()

	// UseHint(pk.hint, Az - 2ᵈ·c·t₁)
	//    = UseHint(pk.hint, w + c·t₀)
	//    = UseHint(pk.hint, r + c·t₀)
	//    = r₁ = w₁.
	w1.UseHint(&Az2dct1, &sig.hint)
	w1.PackW1(w1Packed[:])

	// c' = H(μ, w₁)
	h.Reset()
	_, _ = h.Write(mu[:])
	_, _ = h.Write(w1Packed[:])
	_, _ = h.Read(cp[:])

	return sig.c == cp
}

func GenThCommitment(sk *PrivateKey, rhop [64]byte, nonce uint16, params *ThresholdParams) ([]VecK, []FVec) {
	ws := make([]VecK, params.K)
	sts := make([]FVec, params.K)

	for i := uint16(0); i < params.K; i++ {
		var r, rh VecL
		var e_ VecK

		// [THRESHOLD] Also sample an error for w
		SampleHyperball(&sts[i], params.rPrime, params.nu, rhop, nonce*params.K+i)
		sts[i].Round(&r, &e_)

		// Set w to A y
		rh = r
		rh.NTT()
		for j := 0; j < K; j++ {
			PolyDotHat(&ws[i][j], &sk.A[j], &rh)
			ws[i][j].ReduceLe2Q()
			ws[i][j].InvNTT()

			// [THRESHOLD]
			ws[i][j].Add(&e_[j], &ws[i][j])
			ws[i][j].ReduceLe2Q()
		}

		// Decompose w into w₀ and w₁
		ws[i].NormalizeAssumingLe2Q()
	}

	return ws, sts
}

func AggregateCommitments(wfinals []VecK, ws []VecK) {
	for i := uint16(0); i < uint16(len(ws)); i++ {
		wfinals[i].Add(&wfinals[i], &ws[i])
		wfinals[i].NormalizeAssumingLe2Q()
	}
}

// ComputeMu computes the seed μ for the given message
func ComputeMu(sk *PrivateKey, msg func(io.Writer)) [64]byte {
	//  μ = CRH(tr ‖ msg)
	var mu [64]byte
	h := sha3.NewShake256()
	_, _ = h.Write(sk.Tr[:])
	msg(&h)
	_, _ = h.Read(mu[:])

	return mu
}

func recoverShare(sk *PrivateKey, act uint8, params *ThresholdParams) (s1h VecL, s2h VecK) {
	// Base case, when the party has only one share to use
	if params.T == 1 || params.T == params.N {
		for u := range sk.shares {
			s1h = sk.shares[u].s1h
			s2h = sk.shares[u].s2h
			return
		}
	}

	// Otherwise, we rely on hardcoded sharing patterns
	// They are computed in params/recover.py
	var sharing [][]uint8
	// 2 3 [[5, 3], [6]]
	// 2 4 [[13, 7], [14, 11]]
	// 3 4 [[9, 3], [10, 6], [12, 5]]
	// 2 5 [[29, 15, 27], [30, 23]]
	// 3 5 [[25, 7, 19], [26, 11, 14, 22], [28, 13, 21]]
	// 4 5 [[17, 3], [18, 6, 10], [20, 5, 12], [24, 9]]
	if params.T == 2 && params.N == 3 {
		sharing = [][]uint8{[]uint8{3, 5}, []uint8{6}}
	} else if params.T == 2 && params.N == 4 {
		sharing = [][]uint8{[]uint8{11, 13}, []uint8{7, 14}}
	} else if params.T == 3 && params.N == 4 {
		sharing = [][]uint8{[]uint8{3, 9}, []uint8{6, 10}, []uint8{12, 5}}
	} else if params.T == 2 && params.N == 5 {
		sharing = [][]uint8{[]uint8{27, 29, 23}, []uint8{30, 15}}
	} else if params.T == 3 && params.N == 5 {
		sharing = [][]uint8{[]uint8{25, 11, 19, 13}, []uint8{7, 14, 22, 26}, []uint8{28, 21}}
	} else if params.T == 4 && params.N == 5 {
		sharing = [][]uint8{[]uint8{3, 9, 17}, []uint8{6, 10, 18}, []uint8{12, 5, 20}, []uint8{24}}
	} else if params.T == 2 && params.N == 6 {
		sharing = [][]uint8{[]uint8{61, 47, 55}, []uint8{62, 31, 59}}
	} else if params.T == 3 && params.N == 6 {
		sharing = [][]uint8{[]uint8{27, 23, 43, 57, 39}, []uint8{51, 58, 46, 30, 54}, []uint8{45, 53, 29, 15, 60}}
	} else if params.T == 4 && params.N == 6 {
		sharing = [][]uint8{[]uint8{19, 13, 35, 7, 49}, []uint8{42, 26, 38, 50, 22}, []uint8{52, 21, 44, 28, 37}, []uint8{25, 11, 14, 56, 41}}
	} else if params.T == 5 && params.N == 6 {
		sharing = [][]uint8{[]uint8{3, 5, 33}, []uint8{6, 10, 34}, []uint8{12, 20, 36}, []uint8{9, 24, 40}, []uint8{48, 17, 18}}
	} else {
		panic("not supported yet")
	}

	// Define a permutation to cover the signing set act
	perm := make([]uint8, params.N)
	i1 := 0
	i2 := params.T
	currenti := 0
	for j := uint8(0); j < params.N; j++ {
		if j == sk.Id {
			currenti = i1
		}
		if act&(1<<j) != 0 {
			perm[i1] = j
			i1++
		} else {
			perm[i2] = j
			i2++
		}
	}

	for _, u := range sharing[currenti] {
		// Translate the share index u to the share index u_
		// by applying the permutation
		u_ := uint8(0)
		for i := uint8(0); i < params.N; i++ {
			if u&(1<<i) != 0 {
				u_ |= (1 << perm[i])
			}
		}

		// Add the share to the partial secret
		s1h.Add(&s1h, &sk.shares[u_].s1h)
		s2h.Add(&s2h, &sk.shares[u_].s2h)
	}
	s1h.Normalize()
	s2h.Normalize()

	return
}

func ComputeResponses(sk *PrivateKey, act uint8, mu [64]byte, wfinals []VecK, stws []FVec, params *ThresholdParams) []VecL {
	if act&(1<<sk.Id) == 0 {
		panic("Specified user is not part of the signing set")
	}

	var w1Packed [PolyW1Size * K]byte
	var y VecK
	var w0, w1 VecK
	var c [CTildeSize]byte
	var ch common.Poly

	zs := make([]VecL, params.K)

	h := sha3.NewShake256()

	// Recover the partial secret of the current user corresponding
	// to the signer set act
	s1h, s2h := recoverShare(sk, act, params)

	// For each commitment
	for i := uint16(0); i < params.K; i++ {
		var z VecL
		// Decompose w into w₀ and w₁
		wfinals[i].Decompose(&w0, &w1)

		// c~ = H(μ ‖ w₁)
		w1.PackW1(w1Packed[:])
		h.Reset()
		_, _ = h.Write(mu[:])
		_, _ = h.Write(w1Packed[:])
		_, _ = h.Read(c[:])

		PolyDeriveUniformBall(&ch, c[:])
		ch.NTT()

		// Compute c·s₁
		for j := 0; j < L; j++ {
			z[j].MulHat(&ch, &s1h[j])
			z[j].InvNTT()
		}
		z.Normalize()

		// Compute c*s2
		for j := 0; j < K; j++ {
			y[j].MulHat(&ch, &s2h[j])
			y[j].InvNTT()
		}
		y.Normalize()

		var zf FVec
		zf.From(&z, &y)
		zf.Add(&zf, &stws[i])

		if zf.Excess(params.r, params.nu) {
			continue
		}

		zf.Round(&zs[i], &y)
	}

	return zs
}

func AggregateResponses(zfinals []VecL, zs []VecL) {
	for i := uint16(0); i < uint16(len(zs)); i++ {
		zfinals[i].Add(&zfinals[i], &zs[i])
		// zfinals[i].NormalizeAssumingLe2Q()
		zfinals[i].Normalize()
	}
}

// Sequentially packs each polynomial using Poly.PackLeGamma1().
func PackResponses(zs []VecL, buf []byte) {
	offset := 0
	for i := 0; i < len(zs); i++ {
		zs[i].PackLeGamma1(buf[offset:])
		offset += SingleResponseSize
	}
}

// Sets v to the polynomials packed in buf using VecL.PackLeqEta().
func UnpackResponses(zs []VecL, buf []byte) {
	offset := 0
	for i := 0; i < len(zs); i++ {
		zs[i].UnpackLeGamma1(buf[offset:])
		offset += SingleResponseSize
	}
}

func Combine(pk *PublicKey, msg func(io.Writer), wfinals []VecK, zs []VecL, signature []byte, params *ThresholdParams) bool {
	var mu [64]byte
	var zh VecL
	var Az, Az2dct1, w0, w1, w0pf VecK
	var ch common.Poly
	var w1Packed [PolyW1Size * K]byte
	var sig unpackedSignature

	// μ = CRH(tr ‖ msg)
	h := sha3.NewShake256()
	_, _ = h.Write(pk.Tr[:])
	msg(&h)
	_, _ = h.Read(mu[:])

	// For each commitment
	for i := uint16(0); i < params.K; i++ {
		// Decompose w into w₀ and w₁
		wfinals[i].Decompose(&w0, &w1)

		// Compute Az
		sig.z = zs[i]

		// Ensure ‖z‖_∞ < γ1 - beta.
		if zs[i].Exceeds(Gamma1 - Beta) {
			continue
		}

		zh = zs[i]
		zh.NTT()

		for j := 0; j < K; j++ {
			PolyDotHat(&Az[j], &pk.A[j], &zh)
		}

		// c~ = H(μ ‖ w₁)
		w1.PackW1(w1Packed[:])
		h.Reset()
		_, _ = h.Write(mu[:])
		_, _ = h.Write(w1Packed[:])
		_, _ = h.Read(sig.c[:])

		PolyDeriveUniformBall(&ch, sig.c[:])
		ch.NTT()

		// Next, we compute Az - 2ᵈ·c·t₁.
		Az2dct1.MulBy2toD(&pk.t1)
		Az2dct1.NTT()
		for j := 0; j < K; j++ {
			Az2dct1[j].MulHat(&Az2dct1[j], &ch)
		}
		Az2dct1.Sub(&Az, &Az2dct1)
		Az2dct1.ReduceLe2Q()
		Az2dct1.InvNTT()
		Az2dct1.NormalizeAssumingLe2Q()

		var f VecK
		f.Sub(&Az2dct1, &wfinals[i])
		f.Normalize()

		// Ensure ‖c*t0 - c*s2 - e_2‖_∞ < γ₂.
		if f.Exceeds(Gamma2) {
			continue
		}

		// Decompose w into w₀ and w₁
		wfinals[i].Decompose(&w0, &w1)
		w0pf.Add(&w0, &f)

		w0pf.Normalize()
		hintPop := sig.hint.MakeHint(&w0pf, &w1)

		if hintPop <= Omega {
			sig.Pack(signature)
			return true
		}
	}

	return false
}

// SignTo signs the given message and writes the signature into signature.
//
// For Dilithium this is the top-level signing function. For ML-DSA
// this is ML-DSA.Sign_internal.
//
//nolint:funlen
func SignTo(sk *PrivateKey, msg func(io.Writer), rnd [32]byte, signature []byte) {
	var rhop [64]byte

	if len(signature) < SignatureSize {
		panic("Signature does not fit in that byteslice")
	}

	params := defaultThresholdParams()

	pk := sk.Public()

	// ρ' = CRH(key)
	h := sha3.NewShake256()
	_, _ = h.Write(sk.key[:])
	_, _ = h.Write(rnd[:])
	_, _ = h.Read(rhop[:])

	// Main rejection loop
	attempt := uint16(0)
	for {
		attempt++
		if attempt >= 576 {
			// Depending on the mode, one try has a chance between 1/7 and 1/4
			// of succeeding.  Thus it is safe to say that 576 iterations
			// are enough as (6/7)⁵⁷⁶ < 2⁻¹²⁸.
			panic("This should only happen 1 in  2^{128}: something is wrong.")
		}

		// y = ExpandMask(ρ', key)
		// VecLDeriveUniformLeGamma1(&y, &rhop, yNonce)

		// [THRESHOLD] Also sample an error for w
		w, stw := GenThCommitment(sk, rhop, uint16(attempt), params)

		mu := ComputeMu(sk, msg)
		zs := ComputeResponses(sk, 1, mu, w, stw, params)
		if !Combine(pk, msg, w, zs, signature[:], params) {
			continue
		}
		//
		break
	}
}

// Computes the public key corresponding to this private key.
func (sk *PrivateKey) Public() *PublicKey {
	pk := &PublicKey{
		rho: sk.rho,
		A:   &sk.A,
		Tr:  &sk.Tr,
	}
	computeT0andT1(&sk.A, &sk.shares[1].s1h, &sk.shares[1].s2, &pk.t1)
	pk.t1.PackT1(pk.t1p[:])
	return pk
}

// Equal returns whether the two public keys are equal
func (pk *PublicKey) Equal(other *PublicKey) bool {
	return pk.rho == other.rho && pk.t1 == other.t1
}

// Equal returns whether the two private keys are equal
func (sk *PrivateKey) Equal(other *PrivateKey) bool {
	ret := (subtle.ConstantTimeCompare(sk.rho[:], other.rho[:]) &
		subtle.ConstantTimeCompare(sk.key[:], other.key[:]) &
		subtle.ConstantTimeCompare(sk.Tr[:], other.Tr[:]))

	acc := uint32(0)
	acc |= uint32(sk.Id ^ other.Id)
	acc |= uint32(len(sk.shares) ^ len(other.shares))
	for u, share := range sk.shares {
		othershare, ok := other.shares[u]
		if !ok {
			othershare = &Share{}
		}

		for i := 0; i < L; i++ {
			for j := 0; j < common.N; j++ {
				acc |= share.s1[i][j] ^ othershare.s1[i][j]
			}
		}
		for i := 0; i < K; i++ {
			for j := 0; j < common.N; j++ {
				acc |= share.s2[i][j] ^ othershare.s2[i][j]
			}
		}
	}

	return (ret & subtle.ConstantTimeEq(int32(acc), 0)) == 1
}
