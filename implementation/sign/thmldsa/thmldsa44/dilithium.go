// Code generated from pkg.templ.go. DO NOT EDIT.

// mldsa44 implements NIST signature scheme ML-DSA-44 as defined in FIPS204.
package thmldsa44

import (
	"crypto"
	cryptoRand "crypto/rand"
	"errors"
	"io"
	"math/bits"
	"sync/atomic"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/internal/sha3"
	common "github.com/cloudflare/circl/sign/internal/dilithium"
	"github.com/cloudflare/circl/sign/thmldsa/thmldsa44/internal"
)

const (
	// Size of seed for NewKeyFromSeed
	SeedSize = common.SeedSize

	// Size of a packed PublicKey
	PublicKeySize = internal.PublicKeySize

	// Size of a signature
	SignatureSize = internal.SignatureSize
)

// ThresholdParams contains parameters for threshold ML-DSA-44
type ThresholdParams internal.ThresholdParams

func (params *ThresholdParams) ResponseSize() int {
	return int(params.K) * internal.SingleResponseSize
}

func (params *ThresholdParams) CommitmentSize() int {
	return int(params.K) * internal.SingleCommitmentSize
}

// GetThresholdParams returns recommended parameters for threshold ML-DSA-44
// given threshold T and total number of parties N.
// Returns error if parameters are invalid.
func GetThresholdParams(t, n uint8) (*ThresholdParams, error) {
	p, err := internal.GetThresholdParams(t, n)
	if err != nil {
		return nil, err
	}
	params := ThresholdParams(*p)
	return &params, nil
}

// PublicKey is the type of ML-DSA-44 public key
type PublicKey internal.PublicKey

// PrivateKey is the type of ML-DSA-44 private key
type PrivateKey internal.PrivateKey

// [THRESHOLD] ErrStateAlreadyUsed is returned by Round2 and Round3 when the
// signing state they are given is empty or has already been consumed. Every
// signing attempt has to start from a fresh Round1: two responses computed
// from the same commitment randomness under two different challenges reveal
// the secret share of the signer, as z - z' = (c - c')·s.
var ErrStateAlreadyUsed = errors.New("thmldsa: signing state is empty or already used; each signing attempt needs a fresh Round1")

// [THRESHOLD] attemptState holds the secret state of a single signing attempt:
// the commitment randomness cmtst, and the commitment wbuf it opens to. It is
// referenced by pointer from StRound1 and StRound2, so that every copy of a
// round state shares one "used" flag and consuming any copy consumes them all.
//
// The state moves forward one round at a time: Round2 takes it out of the
// StRound1 it is given and stores it in the StRound2 it returns, and Round3
// consumes it and zeroizes the randomness. It is therefore used for at most
// one response.
type attemptState struct {
	used atomic.Bool
	wbuf []byte
	cmtst []internal.FVec
}

// take marks st as consumed and returns it, or returns nil if st is empty or
// was already consumed. The flag is set atomically, so that two callers racing
// on the same attempt cannot both take it: one wins and the other is rejected.
func (st *attemptState) take() *attemptState {
	if st == nil || !st.used.CompareAndSwap(false, true) {
		return nil
	}
	return st
}

// move consumes st and returns a new attemptState holding its contents, to
// hand the signing attempt over to the next round.
func (st *attemptState) move() *attemptState {
	if st.take() == nil {
		return nil
	}
	next := &attemptState{wbuf: st.wbuf, cmtst: st.cmtst}
	st.wbuf, st.cmtst = nil, nil
	return next
}

// zeroize overwrites the commitment randomness and drops the attempt state.
// The commitment itself is public, so it is only dropped.
func (st *attemptState) zeroize() {
	for i := range st.cmtst {
		st.cmtst[i] = internal.FVec{}
	}
	st.cmtst = nil
	st.wbuf = nil
}

// [THRESHOLD] StRound1 is the state of a signing attempt between Round1 and
// Round2. It carries the secret commitment randomness of the attempt, and is
// consumed by Round2.
//
// It deliberately has no serialized form: single use can only be enforced in
// memory, so a caller that persists an attempt and restores it holds a state
// whose "used" flag says whatever was persisted. Such a caller is responsible
// for making sure each Round1 output yields at most one response, for instance
// by durably marking the state spent before a response leaves the process.
type StRound1 struct {
	st *attemptState
}

// [THRESHOLD] StRound2 is the state of a signing attempt between Round2 and
// Round3. It takes the secret commitment randomness over from StRound1, and is
// consumed by Round3, which zeroizes that randomness. Like StRound1 it has no
// serialized form, for the reason given there.
type StRound2 struct {
	hashes [][32]byte
	mu [64]byte
	act uint8
	st *attemptState
}

// GenerateThresholdKey generates a public key and N private key shares for threshold signing
// using the provided threshold parameters.
func GenerateThresholdKey(rand io.Reader, params *ThresholdParams) (*PublicKey, []PrivateKey, error) {
	if rand == nil {
		rand = cryptoRand.Reader
	}

	// Generate seed
	var seed [SeedSize]byte
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, nil, err
	}

	// Generate N keys from seed
	pk, sks := internal.NewThresholdKeysFromSeed(&seed, (*internal.ThresholdParams)(params))
	sks_ := make([]PrivateKey, len(sks))
	for i, v := range sks {
		sks_[i] = PrivateKey(v)
	}

	return (*PublicKey)(pk), sks_, nil
}

// NewThresholdKeysFromSeed derives a public key and N private key shares using the given seed
// and threshold parameters.
func NewThresholdKeysFromSeed(seed *[SeedSize]byte, params *ThresholdParams) (*PublicKey, []PrivateKey) {
	pk, sks := internal.NewThresholdKeysFromSeed(seed, (*internal.ThresholdParams)(params))
	sks_ := make([]PrivateKey, len(sks))
	for i, v := range sks {
		sks_[i] = PrivateKey(v)
	}

	return (*PublicKey)(pk), sks_
}

// Sample a commitment w.
//
// [THRESHOLD] The returned StRound1 holds the commitment randomness of this
// signing attempt and must be used for exactly one attempt: call Round1 again
// for every new attempt, including after a failed or abandoned one.
func Round1(sk *PrivateKey, params *ThresholdParams) ([]byte, StRound1, error) {
	var rhop [64]byte
	_, err := cryptoRand.Read(rhop[:])
	if err != nil {
		return nil, StRound1{}, err
	}

	cmt := make([]byte, 32)
	wbuf := make([]byte, int(params.K) * internal.SingleCommitmentSize)

	w, tmpcmtst := internal.GenThCommitment(
		(*internal.PrivateKey)(sk),
		rhop,
		0,
		(*internal.ThresholdParams)(params),
	)
	internal.PackW(w, wbuf[:])

	s := sha3.NewShake256()
	s.Write((*internal.PrivateKey)(sk).Tr[:])
	s.Write([]byte{(*internal.PrivateKey)(sk).Id})
	s.Write(wbuf)
	s.Read(cmt[:])

	return cmt, StRound1{st: &attemptState{wbuf: wbuf, cmtst: tmpcmtst}}, nil
}

// Reveal the commitment of round 1 and bind it to (msg, ctx).
//
// [THRESHOLD] Round2 consumes strd1: the state of the signing attempt moves
// into the returned StRound2, and any further use of strd1 (or of a copy of
// it) fails with ErrStateAlreadyUsed. This is what stops the same commitment
// randomness from being bound to a second message.
func Round2(sk *PrivateKey, act uint8, msg, ctx []byte, msgsrd1 [][]byte, strd1 *StRound1, params *ThresholdParams) ([]byte, StRound2, error) {

	if len(ctx) > 255 {
		return nil, StRound2{}, sign.ErrContextTooLong
	}

	// The round 1 messages are commitment hashes broadcast by the other
	// signers: reject malformed ones here rather than panicking on the
	// conversion below.
	for _, h := range msgsrd1 {
		if len(h) != 32 {
			return nil, StRound2{}, errors.New("wrong commitment hash length")
		}
	}

	// [THRESHOLD] Move the attempt state out of strd1, which is spent from
	// here on. Nothing below can fail, so the state is never lost to an error.
	st := strd1.st.move()
	if st == nil {
		return nil, StRound2{}, ErrStateAlreadyUsed
	}
	strd1.st = nil

	// Store hashes for future use
	st2 := StRound2{}
	st2.hashes = make([][32]byte, len(msgsrd1))
	for i, msg := range msgsrd1 {
		st2.hashes[i] = [32]byte(msg)
	}

	st2.mu = internal.ComputeMu((*internal.PrivateKey)(sk), func(w io.Writer) {
		_, _ = w.Write([]byte{0})
		_, _ = w.Write([]byte{byte(len(ctx))})

		if ctx != nil {
			_, _ = w.Write(ctx)
		}
		w.Write(msg)
	})
	st2.act = act
	st2.st = st

	return st.wbuf, st2, nil
}

// Compute a response to sign (msg, ctx) according to the commitments in cmts, with randomness cmtst.
//
// [THRESHOLD] Round3 consumes strd2, and does so even when it goes on to
// return an error: answering a second set of revealed commitments would answer
// a second challenge with the same commitment randomness, which reveals the
// secret share. A failed attempt therefore has to restart from Round1.
func Round3(sk *PrivateKey, msgsrd2 [][]byte, strd2 *StRound2, params *ThresholdParams) ([]byte, error) {
	// [THRESHOLD] Take the attempt state out of strd2 up front, so that every
	// path out of this function leaves the state spent and the randomness
	// zeroized, and any further use of strd2 (or of a copy of it) is rejected.
	st := strd2.st.take()
	if st == nil {
		return nil, ErrStateAlreadyUsed
	}
	strd2.st = nil
	defer st.zeroize()

	if len(msgsrd2) != len(strd2.hashes) || len(msgsrd2) != bits.OnesCount8(strd2.act) {
		return nil, errors.New("wrong number of commitments")
	}

	wtmp := make([]internal.VecK, params.K)
	wfinal := make([]internal.VecK, params.K)

	// Compute wfinal
	j := uint8(0)
	for i := 0; i < len(msgsrd2); i++ {
		// Get the id of the j-th signer
		for strd2.act & (1 << j) == 0 {
			j++
		}

		if len(msgsrd2[i]) != params.CommitmentSize() {
			return nil, errors.New("wrong commitment byte length")
		}

		// Check that the commitments correspond to the one hashed in round 1
		s := sha3.NewShake256()
		s.Write((*internal.PrivateKey)(sk).Tr[:])
		s.Write([]byte{j})
		s.Write(msgsrd2[i])

		var hash [32]byte
		s.Read(hash[:])
		if hash != strd2.hashes[i] {
			return nil, errors.New("wrong commitment")
		}

		internal.UnpackW(wtmp, msgsrd2[i][:])
		internal.AggregateCommitments(wfinal, wtmp)

		j++
	}

	zs := internal.ComputeResponses((*internal.PrivateKey)(sk), strd2.act, strd2.mu, wfinal, st.cmtst, (*internal.ThresholdParams)(params))

	response := make([]byte, params.ResponseSize())
	internal.PackResponses(zs, response[:])
	return response, nil
}

func Combine(pk *PublicKey, msg, ctx []byte, cmts [][]byte, resps [][]byte, sig []byte, params *ThresholdParams) bool {
	zfinal := make([]internal.VecL, params.K)
	ztmp := make([]internal.VecL, params.K)
	wfinal := make([]internal.VecK, params.K)
	wtmp := make([]internal.VecK, params.K)

	if len(resps) < int(params.T) {
		return false // Not enough responses to meet threshold
	}

	// Compute wfinal
	for i := 0; i < len(cmts); i++ {
		if len(cmts[i]) != params.CommitmentSize() {
			return false // wrong commitment byte length
		}

		internal.UnpackW(wtmp, cmts[i][:])
		internal.AggregateCommitments(wfinal, wtmp)
	}

	// Compute zfinal
	for i := 0; i < len(resps); i++ {
		if len(resps[i]) != params.ResponseSize() {
			return false // wrong response byte length
		}

		internal.UnpackResponses(ztmp, resps[i][:])
		internal.AggregateResponses(zfinal, ztmp)
	}

	// Combine
	ret := internal.Combine((*internal.PublicKey)(pk), func(w io.Writer) {
		_, _ = w.Write([]byte{0})
		_, _ = w.Write([]byte{byte(len(ctx))})

		if ctx != nil {
			_, _ = w.Write(ctx)
		}
		w.Write(msg)
	}, wfinal, zfinal, sig[:], (*internal.ThresholdParams)(params))

	return ret
}

// SignTo signs the given message and writes the signature into signature.
// It will panic if signature is not of length at least SignatureSize.
//
// ctx is the optional context string. Errors if ctx is larger than 255 bytes.
// A nil context string is equivalent to an empty context string.
func SignTo(sk *PrivateKey, msg, ctx []byte, randomized bool, sig []byte) error {
	var rnd [32]byte
	if randomized {
		_, err := cryptoRand.Read(rnd[:])
		if err != nil {
			return err
		}
	}

	if len(ctx) > 255 {
		return sign.ErrContextTooLong
	}

	internal.SignTo(
		(*internal.PrivateKey)(sk),
		func(w io.Writer) {
			_, _ = w.Write([]byte{0})
			_, _ = w.Write([]byte{byte(len(ctx))})

			if ctx != nil {
				_, _ = w.Write(ctx)
			}
			w.Write(msg)
		},
		rnd,
		sig,
	)
	return nil
}

// Do not use. Implements ML-DSA.Sign_internal used for compatibility tests.
func (sk *PrivateKey) unsafeSignInternal(msg []byte, rnd [32]byte) []byte {
	var ret [SignatureSize]byte
	internal.SignTo(
		(*internal.PrivateKey)(sk),
		func(w io.Writer) {
			_, _ = w.Write(msg)
		},
		rnd,
		ret[:],
	)
	return ret[:]
}

// Do not use. Implements ML-DSA.Verify_internal used for compatibility tests.
func unsafeVerifyInternal(pk *PublicKey, msg, sig []byte) bool {
	return internal.Verify(
		(*internal.PublicKey)(pk),
		func(w io.Writer) {
			_, _ = w.Write(msg)
		},
		sig,
	)
}

// Verify checks whether the given signature by pk on msg is valid.
//
// ctx is the optional context string. Fails if ctx is larger than 255 bytes.
// A nil context string is equivalent to an empty context string.
func Verify(pk *PublicKey, msg, ctx, sig []byte) bool {
	if len(ctx) > 255 {
		return false
	}
	return internal.Verify(
		(*internal.PublicKey)(pk),
		func(w io.Writer) {
			_, _ = w.Write([]byte{0})
			_, _ = w.Write([]byte{byte(len(ctx))})

			if ctx != nil {
				_, _ = w.Write(ctx)
			}
			_, _ = w.Write(msg)
		},
		sig,
	)
}

// Sets pk to the public key encoded in buf.
func (pk *PublicKey) Unpack(buf *[PublicKeySize]byte) {
	(*internal.PublicKey)(pk).Unpack(buf)
}

// Sets sk to the private key encoded in buf.
func (sk *PrivateKey) Unpack(buf []byte) {
	(*internal.PrivateKey)(sk).Unpack(buf)
}

// Packs the public key into buf.
func (pk *PublicKey) Pack(buf *[PublicKeySize]byte) {
	(*internal.PublicKey)(pk).Pack(buf)
}

// Packs the private key into buf.
func (sk *PrivateKey) Pack(buf []byte) {
	(*internal.PrivateKey)(sk).Pack(buf)
}

// Packs the public key.
func (pk *PublicKey) Bytes() []byte {
	var buf [PublicKeySize]byte
	pk.Pack(&buf)
	return buf[:]
}

// // Packs the private key.
// func (sk *PrivateKey) Bytes() []byte {
// 	var buf [PrivateKeySize]byte
// 	sk.Pack(buf)
// 	return buf[:]
// }

// Packs the public key.
func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	return pk.Bytes(), nil
}

// // Packs the private key.
// func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
// 	return sk.Bytes(), nil
// }

// Unpacks the public key from data.
func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	if len(data) != PublicKeySize {
		return errors.New("packed public key must be of mldsa44.PublicKeySize bytes")
	}
	var buf [PublicKeySize]byte
	copy(buf[:], data)
	pk.Unpack(&buf)
	return nil
}

// // Unpacks the private key from data.
// func (sk *PrivateKey) UnmarshalBinary(data []byte) error {
// 	if len(data) != PrivateKeySize {
// 		return errors.New("packed private key must be of mldsa44.PrivateKeySize bytes")
// 	}
// 	var buf [PrivateKeySize]byte
// 	copy(buf[:], data)
// 	sk.Unpack(&buf)
// 	return nil
// }

// Sign signs the given message.
//
// opts.HashFunc() must return zero, which can be achieved by passing
// crypto.Hash(0) for opts.  rand is ignored.  Will only return an error
// if opts.HashFunc() is non-zero.
//
// This function is used to make PrivateKey implement the crypto.Signer
// interface.  The package-level SignTo function might be more convenient
// to use.
func (sk *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (
	sig []byte, err error) {
	var ret [SignatureSize]byte

	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("dilithium: cannot sign hashed message")
	}
	if err = SignTo(sk, msg, nil, false, ret[:]); err != nil {
		return nil, err
	}

	return ret[:], nil
}

// Computes the public key corresponding to this private key.
//
// Returns a *PublicKey.  The type crypto.PublicKey is used to make
// PrivateKey implement the crypto.Signer interface.
func (sk *PrivateKey) Public() crypto.PublicKey {
	return (*PublicKey)((*internal.PrivateKey)(sk).Public())
}

// Equal returns whether the two private keys equal.
func (sk *PrivateKey) Equal(other crypto.PrivateKey) bool {
	castOther, ok := other.(*PrivateKey)
	if !ok {
		return false
	}
	return (*internal.PrivateKey)(sk).Equal((*internal.PrivateKey)(castOther))
}

// Equal returns whether the two public keys equal.
func (pk *PublicKey) Equal(other crypto.PublicKey) bool {
	castOther, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	return (*internal.PublicKey)(pk).Equal((*internal.PublicKey)(castOther))
}
