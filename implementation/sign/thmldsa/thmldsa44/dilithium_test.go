// Code generated from pkg.templ.go. DO NOT EDIT.

// mldsa44 implements NIST signature scheme ML-DSA-44 as defined in FIPS204.
package thmldsa44

import (
	"encoding/binary"
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
			resps[0], err1 = Round3(&sks[0], msgs2, &st1s[0], &st2s[0], thresholdParams)
			resps[1], err2 = Round3(&sks[1], msgs2, &st1s[1], &st2s[1], thresholdParams)
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

// A StRound1 holds the per-attempt signing randomness. Two responses derived
// from the same StRound1 under two different challenges reveal the secret share
// via z - z' = (c - c')*s, so Round3 must consume a StRound1 at most once.
func TestRound3RejectsReusedStRound1(t *testing.T) {
	var seed [common.SeedSize]byte
	seed[0] = 1
	thresholdParams, err := GetThresholdParams(parties, parties)
	if err != nil {
		t.Fatal(err)
	}
	_, sks := NewThresholdKeysFromSeed(&seed, thresholdParams)
	act := uint8((1 << parties) - 1)
	ctx := []byte{}

	// Round 1: each party commits once.
	msgs1 := make([][]byte, parties)
	st1s := make([]StRound1, parties)
	for i := 0; i < parties; i++ {
		msgs1[i], st1s[i], err = Round1(&sks[i], thresholdParams)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Round 2 for message A (the revealed commitment is message-independent).
	msgs2 := make([][]byte, parties)
	st2s := make([]StRound2, parties)
	for i := 0; i < parties; i++ {
		msgs2[i], st2s[i], err = Round2(&sks[i], act, []byte("message A"), ctx, msgs1, &st1s[i], thresholdParams)
		if err != nil {
			t.Fatal(err)
		}
	}

	// First Round 3 on party 0's StRound1 must succeed.
	if _, err := Round3(&sks[0], msgs2, &st1s[0], &st2s[0], thresholdParams); err != nil {
		t.Fatalf("first Round3 failed: %v", err)
	}

	// Reuse the same StRound1 for a different message: Round2 again, then Round3.
	// The second Round3 must be rejected rather than emitting a second response.
	_, st2b, err := Round2(&sks[0], act, []byte("message B"), ctx, msgs1, &st1s[0], thresholdParams)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Round3(&sks[0], msgs2, &st1s[0], &st2b, thresholdParams); err == nil {
		t.Fatal("second Round3 on a reused StRound1 succeeded; nonce reuse not prevented")
	}
}