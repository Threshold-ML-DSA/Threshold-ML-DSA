// Code generated from pkg.templ.go. DO NOT EDIT.

// mldsa87 implements NIST signature scheme ML-DSA-87 as defined in FIPS204.
package thmldsa87

import (
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	common "github.com/cloudflare/circl/sign/internal/dilithium"
)

const parties = 2

func TestThSignMultiKeys(t *testing.T) {
	var (
		seed [common.SeedSize]byte
		msg  [8]byte
		ctx  [8]byte
		sig [SignatureSize]byte
	)
	for i := uint64(0); i < 30; i++ {
		binary.LittleEndian.PutUint64(seed[:], i)
		thresholdParams, err := GetThresholdParams(parties, parties)
		if err != nil {
			t.Fatal(err)
		}
		pk, sks := NewThresholdKeysFromSeed(&seed, thresholdParams)

		// Sign separately

		success := false
		for attempts := uint64(0); attempts < 100; attempts++ {
			// Compute commitments
			st1s := make([]StRound1, parties)
			msgs1 := make([][]byte, parties)
			for i := 0; i < parties; i++ {
				msgs1[i], st1s[i], err = Round1(&sks[i], thresholdParams)
				if err != nil {
					t.Fatal(err)
				}
			}

			// Compute responses
			st2s := make([]StRound2, parties)
			msgs2 := make([][]byte, parties)
			for i := 0; i < parties; i++ {
				msgs2[i], st2s[i], err = Round2(&sks[i], (1 << parties) - 1, msg[:], ctx[:], msgs1, &st1s[i], thresholdParams)
				if err != nil {
					t.Fatal(err)
				}
			}

			var err1, err2 error
			resps := make([][]byte, 2)
			resps[0], err1 = Round3(&sks[0], msgs2, &st2s[0], thresholdParams)
			resps[1], err2 = Round3(&sks[1], msgs2, &st2s[1], thresholdParams)
			if err1 != nil || err2 != nil {
				t.Fatal()
			}

			ok := Combine(pk, msg[:], ctx[:], msgs2, resps, sig[:], thresholdParams)
			if !ok {
				continue
			}

			t.Log(attempts)
			success = true
			break
		}

		// Verify
		if !success || !Verify(pk, msg[:], ctx[:], sig[:]) {
			t.Fatal()
		}
	}
}

// The state of a signing attempt holds the commitment randomness of that
// attempt. Two responses derived from the same randomness under two different
// challenges reveal the secret share via z - z' = (c - c')*s, so the state has
// to be usable for at most one response: Round2 consumes the StRound1 it is
// given, and Round3 consumes the StRound2.

const (
	msgA = "message A"
	msgB = "message B"
)

// attempt runs round 1 for all parties and returns their broadcast messages
// and states.
func attempt(t *testing.T, sks []PrivateKey, params *ThresholdParams) ([][]byte, []StRound1) {
	t.Helper()
	msgs1 := make([][]byte, parties)
	st1s := make([]StRound1, parties)
	for i := 0; i < parties; i++ {
		var err error
		msgs1[i], st1s[i], err = Round1(&sks[i], params)
		if err != nil {
			t.Fatal(err)
		}
	}
	return msgs1, st1s
}

// reveal runs round 2 for all parties on the given message.
func reveal(t *testing.T, sks []PrivateKey, act uint8, msg string, msgs1 [][]byte, st1s []StRound1, params *ThresholdParams) ([][]byte, []StRound2) {
	t.Helper()
	msgs2 := make([][]byte, parties)
	st2s := make([]StRound2, parties)
	for i := 0; i < parties; i++ {
		var err error
		msgs2[i], st2s[i], err = Round2(&sks[i], act, []byte(msg), nil, msgs1, &st1s[i], params)
		if err != nil {
			t.Fatal(err)
		}
	}
	return msgs2, st2s
}

func testKeys(t *testing.T) ([]PrivateKey, *ThresholdParams, uint8) {
	t.Helper()
	var seed [common.SeedSize]byte
	seed[0] = 1
	params, err := GetThresholdParams(parties, parties)
	if err != nil {
		t.Fatal(err)
	}
	_, sks := NewThresholdKeysFromSeed(&seed, params)
	return sks, params, uint8((1 << parties) - 1)
}

// A second Round2 on the same StRound1 would bind the same commitment
// randomness to a second message.
func TestRound2RejectsReusedStRound1(t *testing.T) {
	sks, params, act := testKeys(t)
	msgs1, st1s := attempt(t, sks, params)

	// A copy taken before the state is consumed must not survive it either.
	st1Copy := st1s[0]

	reveal(t, sks, act, msgA, msgs1, st1s, params)

	if _, _, err := Round2(&sks[0], act, []byte(msgB), nil, msgs1, &st1s[0], params); !errors.Is(err, ErrStateAlreadyUsed) {
		t.Fatalf("second Round2 on a spent StRound1: got %v, want ErrStateAlreadyUsed", err)
	}
	if _, _, err := Round2(&sks[0], act, []byte(msgB), nil, msgs1, &st1Copy, params); !errors.Is(err, ErrStateAlreadyUsed) {
		t.Fatalf("Round2 on a copy of a spent StRound1: got %v, want ErrStateAlreadyUsed", err)
	}
	if _, _, err := Round2(&sks[0], act, []byte(msgB), nil, msgs1, &StRound1{}, params); !errors.Is(err, ErrStateAlreadyUsed) {
		t.Fatalf("Round2 on an empty StRound1: got %v, want ErrStateAlreadyUsed", err)
	}
}

// A second Round3 on the same StRound2 would answer a second challenge with
// the same commitment randomness.
func TestRound3RejectsReusedStRound2(t *testing.T) {
	sks, params, act := testKeys(t)
	msgs1, st1s := attempt(t, sks, params)
	msgs2, st2s := reveal(t, sks, act, msgA, msgs1, st1s, params)

	// A copy taken before the state is consumed must not survive it either.
	st2Copy := st2s[0]

	if _, err := Round3(&sks[0], msgs2, &st2s[0], params); err != nil {
		t.Fatalf("first Round3 failed: %v", err)
	}

	// The randomness is gone, not just flagged as spent. The copy is the only
	// handle left on the attempt state, since Round3 cleared st2s[0].
	if st2Copy.st == nil || st2Copy.st.cmtst != nil || st2Copy.st.wbuf != nil {
		t.Fatal("Round3 did not clear the commitment randomness")
	}

	if _, err := Round3(&sks[0], msgs2, &st2s[0], params); !errors.Is(err, ErrStateAlreadyUsed) {
		t.Fatalf("second Round3 on a spent StRound2: got %v, want ErrStateAlreadyUsed", err)
	}
	if _, err := Round3(&sks[0], msgs2, &st2Copy, params); !errors.Is(err, ErrStateAlreadyUsed) {
		t.Fatalf("Round3 on a copy of a spent StRound2: got %v, want ErrStateAlreadyUsed", err)
	}
	if _, err := Round3(&sks[0], msgs2, &StRound2{}, params); !errors.Is(err, ErrStateAlreadyUsed) {
		t.Fatalf("Round3 on an empty StRound2: got %v, want ErrStateAlreadyUsed", err)
	}
}

// Round3 answers one set of revealed commitments and no other: a failed call
// spends the state as well, so a retry on the same attempt is rejected.
func TestRound3ConsumesStateOnFailure(t *testing.T) {
	sks, params, act := testKeys(t)
	msgs1, st1s := attempt(t, sks, params)
	msgs2, st2s := reveal(t, sks, act, msgA, msgs1, st1s, params)

	// Tamper with a peer's revealed commitment: it no longer matches the hash
	// broadcast in round 1.
	tampered := make([][]byte, len(msgs2))
	copy(tampered, msgs2)
	tampered[1] = make([]byte, len(msgs2[1]))
	copy(tampered[1], msgs2[1])
	tampered[1][0] ^= 1

	if _, err := Round3(&sks[0], tampered, &st2s[0], params); err == nil {
		t.Fatal("Round3 accepted a commitment that does not match its round 1 hash")
	}
	if _, err := Round3(&sks[0], msgs2, &st2s[0], params); !errors.Is(err, ErrStateAlreadyUsed) {
		t.Fatalf("Round3 after a failed Round3: got %v, want ErrStateAlreadyUsed", err)
	}
}

// Malformed peer input is rejected rather than panicking, and leaves the
// attempt usable since nothing has been revealed yet.
func TestRound2RejectsMalformedInput(t *testing.T) {
	sks, params, act := testKeys(t)
	msgs1, st1s := attempt(t, sks, params)

	short := make([][]byte, parties)
	for i := range short {
		short[i] = []byte{0}
	}
	if _, _, err := Round2(&sks[0], act, []byte(msgA), nil, short, &st1s[0], params); err == nil {
		t.Fatal("Round2 accepted a commitment hash of the wrong length")
	}
	if _, _, err := Round2(&sks[0], act, []byte(msgA), nil, msgs1, &st1s[0], params); err != nil {
		t.Fatalf("Round2 after malformed input: %v", err)
	}
}

// Malformed peer input is rejected rather than panicking.
func TestRound3RejectsMalformedInput(t *testing.T) {
	sks, params, act := testKeys(t)

	msgs1, st1s := attempt(t, sks, params)
	_, st2s := reveal(t, sks, act, msgA, msgs1, st1s, params)
	short := make([][]byte, parties)
	for i := range short {
		short[i] = []byte{0}
	}
	if _, err := Round3(&sks[0], short, &st2s[0], params); err == nil {
		t.Fatal("Round3 accepted commitments of the wrong length")
	}

	// More commitments than there are signers in act: the scan for the id of
	// the i-th signer wraps around the mask, and the round 1 hash of that
	// commitment is then looked up out of range.
	msgs1, st1s = attempt(t, sks, params)
	msgs2, st2s := reveal(t, sks, act, msgA, msgs1, st1s, params)
	if _, err := Round3(&sks[0], append(msgs2, msgs2[0]), &st2s[0], params); err == nil {
		t.Fatal("Round3 accepted more commitments than there are signers")
	}
}

// Two callers racing on the same attempt must not both get a response out of
// it. Run under -race as well.
func TestRound3ConcurrentReuse(t *testing.T) {
	sks, params, act := testKeys(t)
	msgs1, st1s := attempt(t, sks, params)
	msgs2, st2s := reveal(t, sks, act, msgA, msgs1, st1s, params)

	var wg sync.WaitGroup
	var responses atomic.Int64
	for i := 0; i < 8; i++ {
		st := st2s[0] // a copy each, all sharing the one attempt
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := Round3(&sks[0], msgs2, &st, params); err == nil {
				responses.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := responses.Load(); got != 1 {
		t.Fatalf("%d concurrent Round3 calls produced a response, want 1", got)
	}
}

// Combine rejects malformed input rather than panicking.
func TestCombineRejectsMalformedInput(t *testing.T) {
	sks, params, act := testKeys(t)
	pk := sks[0].Public().(*PublicKey)
	msgs1, st1s := attempt(t, sks, params)
	msgs2, st2s := reveal(t, sks, act, msgA, msgs1, st1s, params)

	resps := make([][]byte, parties)
	for i := 0; i < parties; i++ {
		var err error
		resps[i], err = Round3(&sks[i], msgs2, &st2s[i], params)
		if err != nil {
			t.Fatal(err)
		}
	}

	sig := make([]byte, SignatureSize)
	if Combine(pk, []byte(msgA), nil, [][]byte{{0}, {0}}, resps, sig, params) {
		t.Fatal("Combine accepted commitments of the wrong length")
	}
	if Combine(pk, []byte(msgA), nil, msgs2, [][]byte{{0}, {0}}, sig, params) {
		t.Fatal("Combine accepted responses of the wrong length")
	}
}
