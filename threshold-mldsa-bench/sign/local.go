package sign

import (
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/cloudflare/circl/sign/thmldsa/thmldsa44"
	"github.com/cloudflare/circl/sign/thmldsa/thmldsa65"
	"github.com/cloudflare/circl/sign/thmldsa/thmldsa87"
	"github.com/montanaflynn/stats"
)

var K int
var Threshold int
var Param int

// Test threshold dilithium
func LocalThresholdDilithiumRun(iter int) {
	var (
		seed [32]byte
		msg  [8]byte
		ctx  [8]byte
	)

	// Global accumulators
	avgSignRound1 := make([]time.Duration, Threshold)
	avgSignRound2 := make([]time.Duration, Threshold)
	avgSignRound3 := make([]time.Duration, Threshold)
	avgCombineDur := time.Duration(0)
	avgPartyRoundBytes := make([][3]int, Threshold)

	if Param == 44 {
		for i := uint64(0); i < uint64(iter); i++ {
			var sig [thmldsa44.SignatureSize]byte
			log.Println("START OF RUN:", i)
			var genDur time.Duration

			copy(msg[:], "message")

			log.Printf("GENERATION OF KEYS for t=%d n=%d", Threshold, K)

			start := time.Now()
			binary.LittleEndian.PutUint64(seed[:], i)
			params, err := thmldsa44.GetThresholdParams(uint8(Threshold), uint8(K))
			if err != nil {
				panic("Error: failed to get threshold parameters.")
			}
			pk, sks := thmldsa44.NewThresholdKeysFromSeed(&seed, params)

			genDur = time.Since(start)
			fmt.Printf("[TIME] GENERATION OF KEYS %s for %d out of %d setting \n", genDur, Threshold, K)

			// Define signer set that will be used for signing
			act := uint8((1 << Threshold) - 1)

			// Accumulators per attempt
			signRound1TotalDur := make([]time.Duration, Threshold)
			signRound2TotalDur := make([]time.Duration, Threshold)
			signRound3TotalDur := make([]time.Duration, Threshold)
			totalCombineDur := time.Duration(0)
			attemptCount := uint64(0)
			combineAttemptCount := uint64(0)

			log.Println("GENERATION OF SIGNATURE")
			// Sign separately
			success := false
			partyRoundBytes := make([][3]int, Threshold)

			for attempts := uint64(0); attempts < 570; attempts++ {
				attemptCount++

				// Compute commitments: round 1
				strd1s := make([]thmldsa44.StRound1, Threshold)
				msgs1 := make([][]byte, Threshold)
				for j := range msgs1 {
					start = time.Now()

					msgs1[j], strd1s[j], _ = thmldsa44.Round1(&sks[j], params)
					signRound1TotalDur[j] += time.Since(start)
				}
				for j, m := range msgs1 {
					partyRoundBytes[j][0] = len(m)
				}

				// Reveal commitments: round 2
				strd2s := make([]thmldsa44.StRound2, Threshold)
				msgs2 := make([][]byte, Threshold)
				for j := range msgs2 {
					start = time.Now()

					msgs2[j], strd2s[j], _ = thmldsa44.Round2(&sks[j], act, msg[:], ctx[:], msgs1, &strd1s[j], params)
					signRound2TotalDur[j] += time.Since(start)
				}
				for j, m := range msgs2 {
					partyRoundBytes[j][1] = len(m)
				}

				// Compute responses: round 3
				msgs3 := make([][]byte, Threshold)
				var err error
				for j := range msgs3 {
					start = time.Now()

					msgs3[j], err = thmldsa44.Round3(&sks[j], msgs2, &strd2s[j], params)
					signRound3TotalDur[j] += time.Since(start)
				}
				if err != nil {
					panic("Error: responses failed.")
				}
				for j, m := range msgs3 {
					partyRoundBytes[j][2] = len(m)
				}

				start = time.Now()
				ok := thmldsa44.Combine(pk, msg[:], ctx[:], msgs2, msgs3, sig[:], params)
				totalCombineDur += time.Since(start)
				combineAttemptCount++
				if !ok {
					continue
				}

				success = true

				break
			}
			fmt.Printf("Run %d:\n", i)
			for p := 0; p < Threshold; p++ {
				fmt.Printf("Party %d - Avg Round 1 Commitment Time: %s\n", p, signRound1TotalDur[p]/time.Duration(attemptCount))
				fmt.Printf("Party %d - Avg Round 2 Reveal Time: %s\n", p, signRound2TotalDur[p]/time.Duration(attemptCount))
				fmt.Printf("Party %d - Avg Round 3 Response Time: %s\n", p, signRound3TotalDur[p]/time.Duration(attemptCount))

				avgSignRound1[p] += signRound1TotalDur[p] / time.Duration(attemptCount)
				avgSignRound2[p] += signRound2TotalDur[p] / time.Duration(attemptCount)
				avgSignRound3[p] += signRound3TotalDur[p] / time.Duration(attemptCount)

				avgPartyRoundBytes[p][0] += partyRoundBytes[p][0]
				avgPartyRoundBytes[p][1] += partyRoundBytes[p][1]
				avgPartyRoundBytes[p][2] += partyRoundBytes[p][2]
			}
			if combineAttemptCount > 0 {
				fmt.Printf("Avg Combine Time per Attempt (over total: %d): %s\n", combineAttemptCount, totalCombineDur/time.Duration(combineAttemptCount))
				avgCombineDur += totalCombineDur / time.Duration(combineAttemptCount)
			} else {
				fmt.Println("No Combine attempts occurred.")
			}

			fmt.Printf("[BYTES PER PARTY, PER ROUND] Iteration %d:\n", i)
			for p := 0; p < Threshold; p++ {
				fmt.Printf("  Party %d:\n", p)
				fmt.Printf("    Round 1: %d bytes\n", partyRoundBytes[p][0])
				fmt.Printf("    Round 2: %d bytes\n", partyRoundBytes[p][1])
				fmt.Printf("    Round 3: %d bytes\n", partyRoundBytes[p][2])
			}

			log.Println("VERIFICATION OF SIGNATURE")
			// Verify
			start = time.Now()
			if !success || !thmldsa44.Verify(pk, msg[:], ctx[:], sig[:]) {
				fmt.Println("Error: verification failed.")
			}
			fmt.Printf("[TIME] VERIFICATION %s for %d out of %d parties \n", time.Since(start), Threshold, K)
		}
	} else if Param == 65 {
		var sig [thmldsa65.SignatureSize]byte

		for i := uint64(0); i < uint64(iter); i++ {
			log.Println("START OF RUN:", i)
			var genDur time.Duration

			copy(msg[:], "message")

			log.Printf("GENERATION OF KEYS for t=%d n=%d", Threshold, K)

			start := time.Now()
			binary.LittleEndian.PutUint64(seed[:], i)
			params, err := thmldsa65.GetThresholdParams(uint8(Threshold), uint8(K))
			if err != nil {
				panic("Error: failed to get threshold parameters.")
			}
			pk, sks := thmldsa65.NewThresholdKeysFromSeed(&seed, params)

			genDur = time.Since(start)
			fmt.Printf("[TIME] GENERATION OF KEYS %s for %d out of %d setting \n", genDur, Threshold, K)

			// Define signer set that will be used for signing
			act := uint8((1 << Threshold) - 1)

			// Accumulators per attempt
			signRound1TotalDur := make([]time.Duration, Threshold)
			signRound2TotalDur := make([]time.Duration, Threshold)
			signRound3TotalDur := make([]time.Duration, Threshold)
			totalCombineDur := time.Duration(0)
			attemptCount := uint64(0)
			combineAttemptCount := uint64(0)

			log.Println("GENERATION OF SIGNATURE")
			// Sign separately
			success := false
			partyRoundBytes := make([][3]int, Threshold)

			for attempts := uint64(0); attempts < 570; attempts++ {
				attemptCount++

				// Compute commitments: round 1
				strd1s := make([]thmldsa65.StRound1, Threshold)
				msgs1 := make([][]byte, Threshold)
				for j := range msgs1 {
					start = time.Now()

					msgs1[j], strd1s[j], _ = thmldsa65.Round1(&sks[j], params)
					signRound1TotalDur[j] += time.Since(start)
				}
				for j, m := range msgs1 {
					partyRoundBytes[j][0] = len(m)
				}

				// Reveal commitments: round 2
				strd2s := make([]thmldsa65.StRound2, Threshold)
				msgs2 := make([][]byte, Threshold)
				for j := range msgs2 {
					start = time.Now()

					msgs2[j], strd2s[j], _ = thmldsa65.Round2(&sks[j], act, msg[:], ctx[:], msgs1, &strd1s[j], params)
					signRound2TotalDur[j] += time.Since(start)
				}
				for j, m := range msgs2 {
					partyRoundBytes[j][1] = len(m)
				}

				// Compute responses: round 3
				msgs3 := make([][]byte, Threshold)
				var err error
				for j := range msgs3 {
					start = time.Now()

					msgs3[j], err = thmldsa65.Round3(&sks[j], msgs2, &strd2s[j], params)
					signRound3TotalDur[j] += time.Since(start)
				}
				if err != nil {
					panic("Error: responses failed.")
				}
				for j, m := range msgs3 {
					partyRoundBytes[j][2] = len(m)
				}

				start = time.Now()
				ok := thmldsa65.Combine(pk, msg[:], ctx[:], msgs2, msgs3, sig[:], params)
				totalCombineDur += time.Since(start)
				combineAttemptCount++
				if !ok {
					continue
				}

				success = true

				break
			}
			fmt.Printf("Run %d:\n", i)
			for p := 0; p < Threshold; p++ {
				fmt.Printf("Party %d - Avg Round 1 Commitment Time: %s\n", p, signRound1TotalDur[p]/time.Duration(attemptCount))
				fmt.Printf("Party %d - Avg Round 2 Reveal Time: %s\n", p, signRound2TotalDur[p]/time.Duration(attemptCount))
				fmt.Printf("Party %d - Avg Round 3 Response Time: %s\n", p, signRound3TotalDur[p]/time.Duration(attemptCount))

				avgSignRound1[p] += signRound1TotalDur[p] / time.Duration(attemptCount)
				avgSignRound2[p] += signRound2TotalDur[p] / time.Duration(attemptCount)
				avgSignRound3[p] += signRound3TotalDur[p] / time.Duration(attemptCount)

				avgPartyRoundBytes[p][0] += partyRoundBytes[p][0]
				avgPartyRoundBytes[p][1] += partyRoundBytes[p][1]
				avgPartyRoundBytes[p][2] += partyRoundBytes[p][2]
			}
			if combineAttemptCount > 0 {
				fmt.Printf("Avg Combine Time per Attempt (over total: %d): %s\n", combineAttemptCount, totalCombineDur/time.Duration(combineAttemptCount))
				avgCombineDur += totalCombineDur / time.Duration(combineAttemptCount)
			} else {
				fmt.Println("No Combine attempts occurred.")
			}

			fmt.Printf("[BYTES PER PARTY, PER ROUND] Iteration %d:\n", i)
			for p := 0; p < Threshold; p++ {
				fmt.Printf("  Party %d:\n", p)
				fmt.Printf("    Round 1: %d bytes\n", partyRoundBytes[p][0])
				fmt.Printf("    Round 2: %d bytes\n", partyRoundBytes[p][1])
				fmt.Printf("    Round 3: %d bytes\n", partyRoundBytes[p][2])
			}

			log.Println("VERIFICATION OF SIGNATURE")
			// Verify
			start = time.Now()
			if !success || !thmldsa65.Verify(pk, msg[:], ctx[:], sig[:]) {
				fmt.Println("Error: verification failed.")
			}
			fmt.Printf("[TIME] VERIFICATION %s for %d out of %d parties \n", time.Since(start), Threshold, K)
		}
	} else if Param == 87 {
		var sig [thmldsa87.SignatureSize]byte

		for i := uint64(0); i < uint64(iter); i++ {
			log.Println("START OF RUN:", i)
			var genDur time.Duration

			copy(msg[:], "message")

			log.Printf("GENERATION OF KEYS for t=%d n=%d", Threshold, K)

			start := time.Now()
			binary.LittleEndian.PutUint64(seed[:], i)
			params, err := thmldsa87.GetThresholdParams(uint8(Threshold), uint8(K))
			if err != nil {
				panic("Error: failed to get threshold parameters.")
			}
			pk, sks := thmldsa87.NewThresholdKeysFromSeed(&seed, params)

			genDur = time.Since(start)
			fmt.Printf("[TIME] GENERATION OF KEYS %s for %d out of %d setting \n", genDur, Threshold, K)

			// Define signer set that will be used for signing
			act := uint8((1 << Threshold) - 1)

			// Accumulators per attempt
			signRound1TotalDur := make([]time.Duration, Threshold)
			signRound2TotalDur := make([]time.Duration, Threshold)
			signRound3TotalDur := make([]time.Duration, Threshold)
			totalCombineDur := time.Duration(0)
			attemptCount := uint64(0)
			combineAttemptCount := uint64(0)

			log.Println("GENERATION OF SIGNATURE")
			// Sign separately
			success := false
			partyRoundBytes := make([][3]int, Threshold)

			for attempts := uint64(0); attempts < 570; attempts++ {
				attemptCount++

				// Compute commitments: round 1
				strd1s := make([]thmldsa87.StRound1, Threshold)
				msgs1 := make([][]byte, Threshold)
				for j := range msgs1 {
					start = time.Now()

					msgs1[j], strd1s[j], _ = thmldsa87.Round1(&sks[j], params)
					signRound1TotalDur[j] += time.Since(start)
				}
				for j, m := range msgs1 {
					partyRoundBytes[j][0] = len(m)
				}

				// Reveal commitments: round 2
				strd2s := make([]thmldsa87.StRound2, Threshold)
				msgs2 := make([][]byte, Threshold)
				for j := range msgs2 {
					start = time.Now()

					msgs2[j], strd2s[j], _ = thmldsa87.Round2(&sks[j], act, msg[:], ctx[:], msgs1, &strd1s[j], params)
					signRound2TotalDur[j] += time.Since(start)
				}
				for j, m := range msgs2 {
					partyRoundBytes[j][1] = len(m)
				}

				// Compute responses: round 3
				msgs3 := make([][]byte, Threshold)
				var err error
				for j := range msgs3 {
					start = time.Now()

					msgs3[j], err = thmldsa87.Round3(&sks[j], msgs2, &strd2s[j], params)
					signRound3TotalDur[j] += time.Since(start)
				}
				if err != nil {
					panic("Error: responses failed.")
				}
				for j, m := range msgs3 {
					partyRoundBytes[j][2] = len(m)
				}

				start = time.Now()
				ok := thmldsa87.Combine(pk, msg[:], ctx[:], msgs2, msgs3, sig[:], params)
				totalCombineDur += time.Since(start)
				combineAttemptCount++
				if !ok {
					continue
				}

				success = true

				break
			}
			fmt.Printf("Run %d:\n", i)
			for p := 0; p < Threshold; p++ {
				fmt.Printf("Party %d - Avg Round 1 Commitment Time: %s\n", p, signRound1TotalDur[p]/time.Duration(attemptCount))
				fmt.Printf("Party %d - Avg Round 2 Reveal Time: %s\n", p, signRound2TotalDur[p]/time.Duration(attemptCount))
				fmt.Printf("Party %d - Avg Round 3 Response Time: %s\n", p, signRound3TotalDur[p]/time.Duration(attemptCount))

				avgSignRound1[p] += signRound1TotalDur[p] / time.Duration(attemptCount)
				avgSignRound2[p] += signRound2TotalDur[p] / time.Duration(attemptCount)
				avgSignRound3[p] += signRound3TotalDur[p] / time.Duration(attemptCount)

				avgPartyRoundBytes[p][0] += partyRoundBytes[p][0]
				avgPartyRoundBytes[p][1] += partyRoundBytes[p][1]
				avgPartyRoundBytes[p][2] += partyRoundBytes[p][2]
			}
			if combineAttemptCount > 0 {
				fmt.Printf("Avg Combine Time per Attempt (over total: %d): %s\n", combineAttemptCount, totalCombineDur/time.Duration(combineAttemptCount))
				avgCombineDur += totalCombineDur / time.Duration(combineAttemptCount)
			} else {
				fmt.Println("No Combine attempts occurred.")
			}

			fmt.Printf("[BYTES PER PARTY, PER ROUND] Iteration %d:\n", i)
			for p := 0; p < Threshold; p++ {
				fmt.Printf("  Party %d:\n", p)
				fmt.Printf("    Round 1: %d bytes\n", partyRoundBytes[p][0])
				fmt.Printf("    Round 2: %d bytes\n", partyRoundBytes[p][1])
				fmt.Printf("    Round 3: %d bytes\n", partyRoundBytes[p][2])
			}

			log.Println("VERIFICATION OF SIGNATURE")
			// Verify
			start = time.Now()
			if !success || !thmldsa87.Verify(pk, msg[:], ctx[:], sig[:]) {
				fmt.Println("Error: verification failed.")
			}
			fmt.Printf("[TIME] VERIFICATION %s for %d out of %d parties \n", time.Since(start), Threshold, K)
		}
	}

	fmt.Printf("\n=== AVERAGED STATS OVER %d RUNS ===\n", iter)
	for p := 0; p < Threshold; p++ {
		fmt.Printf("Party %d - Avg Round 1 Commitment Time: %s\n", p, avgSignRound1[p]/time.Duration(iter))
		fmt.Printf("Party %d - Avg Round 2 Reveal Time: %s\n", p, avgSignRound2[p]/time.Duration(iter))
		fmt.Printf("Party %d - Avg Round 3 Response Time: %s\n", p, avgSignRound3[p]/time.Duration(iter))
		fmt.Printf("Total time, Party %d: %s\n", p, avgSignRound1[p]/time.Duration(iter)+avgSignRound2[p]/time.Duration(iter)+avgSignRound3[p]/time.Duration(iter))
	}

	fmt.Printf("Avg Combine Time per Run: %s\n", avgCombineDur/time.Duration(iter))

	fmt.Println("[AVERAGE BYTES PER PARTY, PER ROUND]")
	for p := 0; p < Threshold; p++ {
		fmt.Printf("  Party %d:\n", p)
		fmt.Printf("    Round 1: %d bytes\n", avgPartyRoundBytes[p][0]/int(iter))
		fmt.Printf("    Round 2: %d bytes\n", avgPartyRoundBytes[p][1]/int(iter))
		fmt.Printf("    Round 3: %d bytes\n", avgPartyRoundBytes[p][2]/int(iter))
	}
}

// printAveragedStats prints the mean, median, and standard deviation for a map of durations averaged over x runs
func printAveragedStats(phaseName string, totalDurations map[int]float64, x int) {
	var values []float64
	for _, totalDuration := range totalDurations {
		values = append(values, totalDuration/float64(x))
	}
	mean, _ := stats.Mean(values)
	median, _ := stats.Median(values)
	stddev, _ := stats.StandardDeviation(values)

	fmt.Printf("%s averaged duration stats over %d runs:\n", phaseName, x)
	fmt.Printf("  Mean: %.3f ms\n", mean)
	fmt.Printf("  Median: %.3f ms\n", median)
	fmt.Printf("  Standard Deviation: %.3f ms\n", stddev)
}
