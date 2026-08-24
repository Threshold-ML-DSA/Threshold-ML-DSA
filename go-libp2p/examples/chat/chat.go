/*
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Juan Batiz-Benet
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * This program demonstrate a simple chat application using p2p communication.
 *
 */
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"os"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"

	"github.com/cloudflare/circl/sign/thmldsa/thmldsa44"
	"github.com/multiformats/go-multiaddr"
)

type ProtocolState struct {
	sync.Mutex
	N      int
	T      int
	ID     int
	Params *thmldsa44.ThresholdParams
	pk     *thmldsa44.PublicKey
	SKs    []thmldsa44.PrivateKey

	Msgs1 [][]byte
	Strd1 thmldsa44.StRound1

	Msgs2 [][]byte
	Strd2 thmldsa44.StRound2

	Msgs3 [][]byte

	CompletedR1 int
	CompletedR2 int

	done bool

	PingSentTime time.Time
}

func handleStream(rw *bufio.ReadWriter, state *ProtocolState, signature *[]byte, done chan struct{}) {
	go readData(rw, state, signature, done)
	go runProtocolLoop(rw, state)
}

func makeStreamHandler(state *ProtocolState, signature *[]byte, done chan struct{}) network.StreamHandler {
	return func(s network.Stream) {
		log.Println("Got a new stream!")

		rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))
		handleStream(rw, state, signature, done)
	}
}

// Combine the signature
func runCombine(state *ProtocolState, msg, ctx []byte, pk *thmldsa44.PublicKey, sigOut *[]byte, done chan struct{}) {
	var sig [thmldsa44.SignatureSize]byte

	start := time.Now()

	ok := thmldsa44.Combine(
		pk,
		msg,
		ctx,
		state.Msgs2,
		state.Msgs3,
		sig[:],
		state.Params,
	)

	combineDur := time.Since(start)
	log.Printf("[TIME] COMBINATION  %s for 2 parties out of %d", combineDur, state.N)

	if !ok {
		return
	}

	*sigOut = make([]byte, thmldsa44.SignatureSize)
	copy(*sigOut, sig[:])

	log.Printf("Combine success! The signature is: %x", *sigOut)

	done <- struct{}{}
}

func readData(rw *bufio.ReadWriter, state *ProtocolState, signature *[]byte, done chan struct{}) {
	for {
		roundTag, err := rw.ReadString('\n')
		if err != nil {
			log.Println("Failed to read round tag:", err)
			return
		}

		lenStr, err := rw.ReadString('\n')
		if err != nil {
			log.Println("Failed to read message length:", err)
			return
		}

		if lenStr != "\n" {
			fmt.Printf("\x1b[32m%s\x1b[0m> ", lenStr)
		}

		var msgLen int
		fmt.Sscanf(lenStr, "%d\n", &msgLen)

		msg := make([]byte, msgLen)
		_, err = io.ReadFull(rw, msg)
		if err != nil {
			log.Println("Failed to read message content:", err)
			return
		}

		otherID := 1 - state.ID
		state.Lock()

		switch roundTag {
		case "R1\n":
			state.Msgs1[otherID] = msg
			state.CompletedR1++
			log.Printf("Received Round1 (%d/%d)", state.CompletedR1, state.T-1)
		case "R2\n":
			state.Msgs2[otherID] = msg
			state.CompletedR2++
			log.Printf("Received Round2 (%d/%d)", state.CompletedR2, state.T-1)
		case "R3\n":
			state.Msgs3[otherID] = msg
			log.Printf("Received Round3 (%d/%d)", len(state.Msgs3), state.T-1)
			if state.done == true {
				go runCombine(state, []byte("the message"), []byte(""), state.pk, signature, done)
			}
		// LOG messages to measure latency
		case "PING\n":
			rw.WriteString("PONG\n")
			rw.WriteString("0\n")
			rw.Flush()
		case "PONG\n":
			rtt := time.Since(state.PingSentTime)
			log.Printf("[LAN LATENCY] Round-trip time: %s", rtt)
		}

		state.Unlock()
	}
}

func runProtocolLoop(rw *bufio.ReadWriter, state *ProtocolState) {
	// Measure LAN latency once before starting rounds
	if state.ID == 0 {
		state.PingSentTime = time.Now()
		rw.WriteString("PING\n")
		rw.WriteString("0\n")
		rw.Flush()
		log.Println("Sent PING for LAN latency test")
	}

	// Accumulators per attempt
	signRound1TotalDur := make([]time.Duration, 2)
	signRound2TotalDur := make([]time.Duration, 2)
	signRound3TotalDur := make([]time.Duration, 2)
	networkRound1Dur := make([]time.Duration, 2)
	networkRound2Dur := make([]time.Duration, 2)
	networkRound3Dur := make([]time.Duration, 2)

	attemptCount := uint64(0)

	for attempt := 0; attempt < 570; attempt++ {
		attemptCount++
		log.Printf("Starting attempt %d", attempt)
		log.Printf("Peer ID %d", state.ID)

		start := time.Now()
		msg1, stdr1, err := thmldsa44.Round1(&state.SKs[state.ID], state.Params)
		if err != nil {
			log.Printf("Round1 failed: %v\n", err)
			continue
		}
		signRound1TotalDur[state.ID] += time.Since(start)

		state.Lock()
		state.Strd1 = stdr1
		index := state.ID
		state.Msgs1[index] = msg1
		state.Unlock()

		netStart := time.Now()
		rw.WriteString("R1\n")
		rw.WriteString(fmt.Sprintf("%d\n", len(msg1)))
		rw.Flush()
		rw.Write(msg1)
		rw.Flush()
		networkRound1Dur[state.ID] += time.Since(netStart)
		log.Println("Sent Round1")

		for {
			state.Lock()
			if state.CompletedR1 >= state.T-1 {
				state.CompletedR1 = 0
				state.Unlock()
				break
			}
			state.Unlock()
		}

		act := uint8((1 << 2) - 1)
		start = time.Now()
		msg2, stdr2, err := thmldsa44.Round2(
			&state.SKs[state.ID],
			act,
			[]byte("the message"),
			[]byte(""),
			state.Msgs1,
			&state.Strd1,
			state.Params,
		)
		signRound2TotalDur[state.ID] += time.Since(start)
		if err != nil {
			log.Println("Round2 failed:", err)
			continue
		}

		state.Lock()
		state.Strd2 = stdr2
		state.Msgs2[index] = msg2
		state.Unlock()

		netStart = time.Now()
		rw.WriteString("R2\n")
		rw.WriteString(fmt.Sprintf("%d\n", len(msg2)))
		rw.Flush()
		rw.Write(msg2)
		rw.Flush()
		networkRound2Dur[state.ID] += time.Since(netStart)
		log.Println("Sent Round2")

		for {
			state.Lock()
			if state.CompletedR2 >= state.T-1 {
				state.Unlock()
				state.CompletedR2 = 0
				break
			}
			state.Unlock()
		}

		start = time.Now()
		msg3, err := thmldsa44.Round3(
			&state.SKs[state.ID],
			state.Msgs2,
			&state.Strd2,
			state.Params,
		)
		signRound3TotalDur[state.ID] += time.Since(start)
		if err != nil {
			log.Println("Round3 failed:", err)
			continue
		}

		state.Msgs3[index] = msg3

		netStart = time.Now()
		rw.WriteString("R3\n")
		rw.WriteString(fmt.Sprintf("%d\n", len(msg3)))
		rw.Flush()
		rw.Write(msg3)
		rw.Flush()
		networkRound3Dur[state.ID] += time.Since(netStart)
		log.Println("Sent Round3")

		if attempt == 569 {
			state.done = true
		}
	}

	// Print times
	fmt.Printf("Party %d - Avg Round 1 Local Computation Time: %s\n", state.ID, signRound1TotalDur[state.ID]/time.Duration(attemptCount))
	fmt.Printf("Party %d - Avg Round 1 Network Send Time: %s\n", state.ID, networkRound1Dur[state.ID]/time.Duration(attemptCount))
	fmt.Printf("Party %d - Avg Round 2 Local Computation Time: %s\n", state.ID, signRound2TotalDur[state.ID]/time.Duration(attemptCount))
	fmt.Printf("Party %d - Avg Round 2 Network Send Time: %s\n", state.ID, networkRound2Dur[state.ID]/time.Duration(attemptCount))
	fmt.Printf("Party %d - Avg Round 3 Local Computation Time: %s\n", state.ID, signRound3TotalDur[state.ID]/time.Duration(attemptCount))
	fmt.Printf("Party %d - Avg Round 3 Network Send Time: %s\n", state.ID, networkRound3Dur[state.ID]/time.Duration(attemptCount))
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sourcePort := flag.Int("sp", 0, "Source port number")
	dest := flag.String("d", "", "Destination multiaddr string")

	// The id of the party
	id := flag.Int("id", 0, "Party ID (0, 1, etc.)")
	// The n number of parties
	n := flag.Int("n", 6, "Total number of parties")

	help := flag.Bool("help", false, "Display help")
	debug := flag.Bool("debug", false, "Debug generates the same node ID on every execution")

	flag.Parse()

	if *help {
		fmt.Printf("This program demonstrates a simple p2p threshold chat application using libp2p\n\n")
		fmt.Println("Usage:")
		fmt.Println("  ./chat -sp <SOURCE_PORT> -id <ID> -n <TOTAL_PARTIES>")
		fmt.Println("To connect:")
		fmt.Println("  ./chat -d <MULTIADDR> -id <ID> -n <TOTAL_PARTIES>")

		os.Exit(0)
	}

	// If debug is enabled, use a constant random source to generate the peer ID. Only useful for debugging,
	// off by default. Otherwise, it uses rand.Reader.
	var r io.Reader
	if *debug {
		// Use the port number as the randomness source.
		// This will always generate the same host ID on multiple executions, if the same port number is used.
		// Never do this in production code.
		r = mrand.New(mrand.NewSource(int64(*sourcePort)))
	} else {
		r = rand.Reader
	}

	h, err := makeHost(*sourcePort, r)
	if err != nil {
		log.Println(err)
		return
	}

	var genDur time.Duration
	start := time.Now()

	var seed [32]byte
	binary.LittleEndian.PutUint64(seed[:], 1)
	params, _ := thmldsa44.GetThresholdParams(uint8(2), uint8(*n))
	pk, sk := thmldsa44.NewThresholdKeysFromSeed(&seed, params)

	genDur = time.Since(start)
	log.Printf("[TIME] GENERATION OF KEYS %s for 2 parties out of %d", genDur, *n)

	state := &ProtocolState{
		N:      *n,
		T:      2,
		ID:     *id,
		Params: params,
		SKs:    sk,
		pk:     pk,
		Msgs1:  make([][]byte, 2),
		Msgs2:  make([][]byte, 2),
		Msgs3:  make([][]byte, 2),
		done:   false,
	}
	var signature []byte
	done := make(chan struct{})

	if *dest == "" {
		startPeer(ctx, h, makeStreamHandler(state, &signature, done), state.ID, *n)
	} else {
		rw, err := startPeerAndConnect(ctx, h, *dest)
		if err != nil {
			log.Println(err)
			return
		}

		// Create a thread to read and write data.
		go readData(rw, state, &signature, done)
		go runProtocolLoop(rw, state)
	}

	<-done // wait for combine

	verDur := time.Since(start)
	if !thmldsa44.Verify(state.pk, []byte("the message"), []byte(""), signature) {
		fmt.Println("Signature verification failed.")
	} else {
		fmt.Println("Signature verified successfully.")
	}
	log.Printf("[TIME] VERIFICATION OF SIGS %s for 2 parties out of %d", verDur, n)
}

func makeHost(port int, randomness io.Reader) (host.Host, error) {
	// Creates a new RSA key pair for this host.
	prvKey, _, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, randomness)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	// 0.0.0.0 will listen on any interface device.
	sourceMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port))

	// libp2p.New constructs a new libp2p Host.
	// Other options can be added here.
	return libp2p.New(
		libp2p.ListenAddrs(sourceMultiAddr),
		libp2p.Identity(prvKey),
	)
}

func startPeer(ctx context.Context, h host.Host, streamHandler network.StreamHandler, ID, n int) {
	// Set a function as stream handler.
	// This function is called when a peer connects, and starts a stream with this protocol.
	// Only applies on the receiving side.
	h.SetStreamHandler("/chat/1.0.0", streamHandler)

	// Let's get the actual TCP port from our listen multiaddr, in case we're using 0 (default; random available port).
	var port string
	for _, la := range h.Network().ListenAddresses() {
		if p, err := la.ValueForProtocol(multiaddr.P_TCP); err == nil {
			port = p
			break
		}
	}

	if port == "" {
		log.Println("was not able to find actual local port")
		return
	}

	log.Printf("Run './chat -d /ip4/127.0.0.1/tcp/%v/p2p/%s -id %d -n %d' on another console.\n", port, h.ID(), ID+1, n)
	log.Println("You can replace 127.0.0.1 with public IP as well.")
	log.Println("Waiting for incoming connection")
	log.Println()
}

func startPeerAndConnect(ctx context.Context, h host.Host, destination string) (*bufio.ReadWriter, error) {
	log.Println("This node's multiaddresses:")
	for _, la := range h.Addrs() {
		log.Printf(" - %v\n", la)
	}
	log.Println()

	// Turn the destination into a multiaddr.
	maddr, err := multiaddr.NewMultiaddr(destination)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	// Extract the peer ID from the multiaddr.
	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	// Add the destination's peer multiaddress in the peerstore.
	// This will be used during connection and stream creation by libp2p.
	h.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)

	// Start a stream with the destination.
	// Multiaddress of the destination peer is fetched from the peerstore using 'peerId'.
	s, err := h.NewStream(context.Background(), info.ID, "/chat/1.0.0")
	if err != nil {
		log.Println(err)
		return nil, err
	}
	log.Println("Established connection to destination")

	// Create a buffered stream so that read and writes are non-blocking.
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	return rw, nil
}
