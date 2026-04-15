// Code generated from pkg.templ.go. DO NOT EDIT.

// mldsa65 implements NIST signature scheme ML-DSA-65 as defined in FIPS204.
package thmldsa65

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