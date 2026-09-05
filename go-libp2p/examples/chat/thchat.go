// Multi-party libp2p chat with threshold ML-DSA (sequential 570 attempts)
// Build: go build -o thchat
// Example (3 parties, T=2, fixed 570 attempts):
//   # Terminal A (listener)
//   ./thchat -sp 0 -t 2 -n 3
//   # Terminal B (dial A)
//   ./thchat -sp 0 -t 2 -n 3 -d <ADDR_A>
//   # Terminal C (dial A,B)
//   ./thchat -sp 0 -t 2 -n 3 -d <ADDR_A>,<ADDR_B>
//
// Behavior:
// - Exactly N parties (including self) must be connected to start.
// - Party 0 (leader) runs Combine for that attempt; it calls Verify ONLY if Combine==true.
// - On the first successful Combine, leader broadcasts DONE and all parties stop.

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/multiformats/go-multiaddr"

	"github.com/cloudflare/circl/sign/thmldsa/thmldsa44"
)

const chatProto = "/chat/1.0.0"
const Attempts = 570 // fixed

// Wire message for protocol frames.
type WireMsg struct {
	Type    string `json:"type"` // "START","R1","R2","R3","DONE","ERR"
	Attempt int    `json:"attempt"`
	From    string `json:"from"`
	Payload []byte `json:"payload"`
}

// Node information
type stLocal struct {
	St1 thmldsa44.StRound1
	St2 thmldsa44.StRound2
}

type ChatNode struct {
	host  host.Host
	mu    sync.RWMutex
	peers map[peer.ID]*bufio.ReadWriter

	// config
	N int
	T int

	// derived when N are present
	started    bool
	partyIndex int
	order      []peer.ID

	// session crypto
	params *thmldsa44.ThresholdParams
	pk     *thmldsa44.PublicKey
	sk     *thmldsa44.PrivateKey
	msg    []byte
	ctx    []byte

	// inboxes (attempt -> from -> payload)
	rmu sync.Mutex
	r1  map[int]map[string][]byte
	r2  map[int]map[string][]byte
	r3  map[int]map[string][]byte

	// local per-attempt state
	stMu        sync.Mutex
	stByAttempt map[int]*stLocal

	// run control
	done   bool
	doneCh chan struct{}

	// seed from leader
	startSeedCh chan []byte
}

func NewChatNode(h host.Host) *ChatNode {
	return &ChatNode{
		host:        h,
		peers:       make(map[peer.ID]*bufio.ReadWriter),
		r1:          make(map[int]map[string][]byte),
		r2:          make(map[int]map[string][]byte),
		r3:          make(map[int]map[string][]byte),
		stByAttempt: make(map[int]*stLocal),
		doneCh:      make(chan struct{}),
		startSeedCh: make(chan []byte, 1),
	}
}

// Active-set helpers (first T parties in sorted order)
func (c *ChatNode) actMask() uint8        { return uint8((1 << c.T) - 1) }
func (c *ChatNode) isActive(idx int) bool { return idx < c.T }
func (c *ChatNode) filterByAct(all [][]byte) [][]byte {
	out := make([][]byte, 0, c.T)
	for i := range c.order {
		if c.isActive(i) {
			out = append(out, all[i])
		}
	}
	return out
}

// Peer management
func (c *ChatNode) addPeer(id peer.ID, rw *bufio.ReadWriter) {
	c.mu.Lock()
	c.peers[id] = rw
	c.mu.Unlock()
	c.recomputeOrder()
	c.maybeStart()
}

func (c *ChatNode) removePeer(id peer.ID) {
	c.mu.Lock()
	delete(c.peers, id)
	c.mu.Unlock()
}

func (c *ChatNode) recomputeOrder() {
	c.mu.Lock()
	ids := make([]peer.ID, 0, len(c.peers)+1)
	ids = append(ids, c.host.ID())
	for id := range c.peers {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	c.order = ids
	for i, id := range ids {
		if id == c.host.ID() {
			c.partyIndex = i
			break
		}
	}
	c.mu.Unlock()
}

func (c *ChatNode) maybeStart() {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return
	}
	if len(c.peers)+1 < c.N {
		c.mu.Unlock()
		return
	} // wait for N, not T
	c.started = true
	pi := c.partyIndex
	c.mu.Unlock()
	log.Printf("All %d parties connected. I am party %d.", c.N, pi)
	go c.runSigningSession()
}

// IO helpers
func sendJSON(rw *bufio.ReadWriter, m WireMsg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if _, err := rw.Write(b); err != nil {
		return err
	}
	if _, err := rw.WriteString("\n"); err != nil {
		return err
	}
	return rw.Flush()
}

func (c *ChatNode) broadcastJSON(m WireMsg) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for id, rw := range c.peers {
		if err := sendJSON(rw, m); err != nil {
			log.Printf("send to %s failed: %v", shortID(id), err)
		}
	}
}

// Streams
func (c *ChatNode) handleStream(s network.Stream) {
	peerID := s.Conn().RemotePeer()
	log.Printf(">> inbound stream from %s\n", shortID(peerID))
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))
	c.addPeer(peerID, rw)
	go func(id peer.ID, r *bufio.Reader) {
		defer func() { _ = s.Close(); c.removePeer(id); log.Printf("<< %s disconnected\n", shortID(id)) }()
		for {
			str, err := r.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					log.Printf("read error from %s: %v", shortID(id), err)
				}
				return
			}
			str = strings.TrimRight(str, "\r\n")
			if len(str) == 0 {
				continue
			}
			var wm WireMsg
			if err := json.Unmarshal([]byte(str), &wm); err != nil || wm.Type == "" {
				fmt.Printf("\x1b[32m%s\x1b[0m\n", str)
				continue
			}
			c.onWireMsg(wm)
		}
	}(peerID, rw.Reader)
}

func (c *ChatNode) connectAndOpen(ctx context.Context, maddr string) error {
	ma, err := multiaddr.NewMultiaddr(maddr)
	if err != nil {
		return fmt.Errorf("invalid multiaddr %q: %w", maddr, err)
	}
	info, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		return fmt.Errorf("addr->peerinfo failed: %w", err)
	}
	c.host.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)
	s, err := c.host.NewStream(ctx, info.ID, chatProto)
	if err != nil {
		return fmt.Errorf("new stream failed: %w", err)
	}
	log.Printf("connected to %s", shortID(info.ID))
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))
	c.addPeer(info.ID, rw)
	go func(id peer.ID, r *bufio.Reader) {
		defer func() { _ = s.Close(); c.removePeer(id); log.Printf("<< %s disconnected\n", shortID(id)) }()
		for {
			str, err := r.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					log.Printf("read error from %s: %v", shortID(id), err)
				}
				return
			}
			str = strings.TrimRight(str, "\r\n")
			if len(str) == 0 {
				continue
			}
			var wm WireMsg
			if err := json.Unmarshal([]byte(str), &wm); err != nil || wm.Type == "" {
				fmt.Printf("\x1b[32m%s\x1b[0m\n", str)
				continue
			}
			c.onWireMsg(wm)
		}
	}(info.ID, rw.Reader)
	return nil
}

// Protocol handlers
func (c *ChatNode) onWireMsg(m WireMsg) {
	switch m.Type {
	case "START":
		select {
		case c.startSeedCh <- append([]byte(nil), m.Payload...):
		default:
		}
	case "R1", "R2", "R3":
		c.ingest(m.Type, m.Attempt, m.From, m.Payload)
	case "DONE":
		c.markDone()
	case "ERR":
		log.Printf("ERR from %s on attempt %d", shortIDStr(m.From), m.Attempt)
	default:
		log.Printf("unknown msg type %q", m.Type)
	}
}

func (c *ChatNode) markDone() {
	c.rmu.Lock()
	if !c.done {
		c.done = true
		close(c.doneCh)
	}
	c.rmu.Unlock()
}

func (c *ChatNode) ingest(round string, attempt int, from string, payload []byte) {
	c.rmu.Lock()
	switch round {
	case "R1":
		if c.r1 == nil {
			c.r1 = make(map[int]map[string][]byte)
		}
		if c.r1[attempt] == nil {
			c.r1[attempt] = make(map[string][]byte)
		}
		c.r1[attempt][from] = append([]byte(nil), payload...)
	case "R2":
		if c.r2 == nil {
			c.r2 = make(map[int]map[string][]byte)
		}
		if c.r2[attempt] == nil {
			c.r2[attempt] = make(map[string][]byte)
		}
		c.r2[attempt][from] = append([]byte(nil), payload...)
	case "R3":
		if c.r3 == nil {
			c.r3 = make(map[int]map[string][]byte)
		}
		if c.r3[attempt] == nil {
			c.r3[attempt] = make(map[string][]byte)
		}
		c.r3[attempt][from] = append([]byte(nil), payload...)
	}
	c.rmu.Unlock()
}

func (c *ChatNode) waitAll(round string, a int) bool {
	// returns false if DONE was signaled while waiting
	for {
		select {
		case <-c.doneCh:
			return false
		default:
		}
		c.rmu.Lock()
		var got int
		switch round {
		case "R1":
			if c.r1[a] != nil {
				got = len(c.r1[a])
			}
		case "R2":
			if c.r2[a] != nil {
				got = len(c.r2[a])
			}
		case "R3":
			if c.r3[a] != nil {
				got = len(c.r3[a])
			}
		}
		need := c.T
		c.rmu.Unlock()
		if got >= need {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (c *ChatNode) collectRound(round string, a int) [][]byte {
	c.rmu.Lock()
	order := append([]peer.ID{}, c.order...)
	var snap map[string][]byte
	switch round {
	case "R1":
		snap = c.r1[a]
	case "R2":
		snap = c.r2[a]
	case "R3":
		snap = c.r3[a]
	}
	c.rmu.Unlock()
	out := make([][]byte, len(order))
	for i, id := range order {
		out[i] = snap[id.String()]
	}
	return out
}

// Main signature run as sequential attempts
func (c *ChatNode) runSigningSession() {
	log.Printf("START OF RUN: threshold=%d, n=%d", c.T, c.N)

	// Message and ctx
	c.msg = make([]byte, 32)
	copy(c.msg, []byte("message")) // You can change me if wanted
	c.ctx = make([]byte, 48)

	// Params (note: our usage of N and K)
	params, err := thmldsa44.GetThresholdParams(uint8(c.T), uint8(c.N))
	if err != nil {
		log.Fatalf("Get params error: %v", err)
	}
	c.params = params

	// Shared seed from leader (party 0)
	var seed [32]byte
	if c.partyIndex == 0 {
		if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
			log.Fatalf("seed: %v", err)
		}
		c.broadcastJSON(WireMsg{Type: "START", Attempt: -1, From: c.host.ID().String(), Payload: seed[:]})
	} else {
		seedBytes := <-c.startSeedCh
		if len(seedBytes) != 32 {
			log.Fatalf("bad seed len %d", len(seedBytes))
		}
		copy(seed[:], seedBytes)
	}

	// Keygen
	start := time.Now()
	pk, sks := thmldsa44.NewThresholdKeysFromSeed(&seed, c.params)
	log.Printf("[TIME] GENERATION OF KEYS %s for t=%d n=%d", time.Since(start), c.T, c.N)
	c.pk = pk
	my := sks[c.partyIndex]
	c.sk = &my

	// Attempts 0..569, each does R1->R2->R3; leader tries Combine and Verify if ok, then DONE.
	for a := 0; a < Attempts; a++ {
		select {
		case <-c.doneCh:
			return
		default:
		}

		var st1 thmldsa44.StRound1
		var st2 thmldsa44.StRound2

		// Round 1 (only active parties emit)
		if c.isActive(c.partyIndex) {
			msg1, st1local, err := thmldsa44.Round1(c.sk, c.params)
			if err != nil {
				log.Printf("R1 err a=%d: %v", a, err)
				continue
			}
			st1 = st1local
			c.saveState1(a, st1)
			c.broadcastJSON(WireMsg{Type: "R1", Attempt: a, From: c.host.ID().String(), Payload: msg1})
			c.ingest("R1", a, c.host.ID().String(), msg1)
		}
		if !c.waitAll("R1", a) {
			return
		}

		// Round 2 (filter to T active msgs)
		msgs1All := c.collectRound("R1", a)
		msgs1 := c.filterByAct(msgs1All)
		if c.isActive(c.partyIndex) {
			act := c.actMask()
			msg2, st2local, err := thmldsa44.Round2(c.sk, act, c.msg, c.ctx, msgs1, &st1, c.params)
			if err != nil {
				log.Printf("R2 err a=%d: %v", a, err)
				continue
			}
			st2 = st2local
			c.saveState2(a, st2)
			c.broadcastJSON(WireMsg{Type: "R2", Attempt: a, From: c.host.ID().String(), Payload: msg2})
			c.ingest("R2", a, c.host.ID().String(), msg2)
		}
		if !c.waitAll("R2", a) {
			return
		}

		// Round 3 (filter to T active msgs)
		msgs2All := c.collectRound("R2", a)
		msgs2 := c.filterByAct(msgs2All)
		if c.isActive(c.partyIndex) {
			msg3, err := thmldsa44.Round3(c.sk, msgs2, &st2, c.params)
			if err != nil {
				log.Printf("R3 err a=%d: %v", a, err)
				continue
			}
			c.broadcastJSON(WireMsg{Type: "R3", Attempt: a, From: c.host.ID().String(), Payload: msg3})
			c.ingest("R3", a, c.host.ID().String(), msg3)
		}
		if !c.waitAll("R3", a) {
			return
		}

		// Combine (leader only) using filtered T-length arrays. Verify ONLY if combine is true.
		if c.partyIndex == 0 {
			sig := make([]byte, thmldsa44.SignatureSize)
			msgs2C := c.filterByAct(c.collectRound("R2", a))
			msgs3C := c.filterByAct(c.collectRound("R3", a))
			start := time.Now()
			ok := thmldsa44.Combine(c.pk, c.msg, c.ctx, msgs2C, msgs3C, sig, c.params)
			if !ok {
				continue
			}
			log.Printf("[attempt %d] Combine ok in %s", a, time.Since(start))
			if !thmldsa44.Verify(c.pk, c.msg, c.ctx, sig) {
				log.Printf("[attempt %d] Verify failed (unexpected)", a)
				continue
			}
			log.Printf("[attempt %d] Signature verified.", a)
			c.broadcastJSON(WireMsg{Type: "DONE", Attempt: a, From: c.host.ID().String()})
			c.markDone()
			return
		}
	}
}

func (c *ChatNode) saveState1(a int, st1 thmldsa44.StRound1) {
	c.stMu.Lock()
	defer c.stMu.Unlock()
	s := c.stByAttempt[a]
	if s == nil {
		s = &stLocal{}
		c.stByAttempt[a] = s
	}
	s.St1 = st1
}

func (c *ChatNode) saveState2(a int, st2 thmldsa44.StRound2) {
	c.stMu.Lock()
	defer c.stMu.Unlock()
	s := c.stByAttempt[a]
	if s == nil {
		s = &stLocal{}
		c.stByAttempt[a] = s
	}
	s.St2 = st2
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sourcePort := flag.Int("sp", 0, "Source port number (0 for random)")
	dest := flag.String("d", "", "Comma-separated destination multiaddr(s)")
	help := flag.Bool("help", false, "Display help")
	debug := flag.Bool("debug", false, "Deterministic host ID for a given port (debug only)")
	Threshold := flag.Int("t", 2, "Threshold T")
	N := flag.Int("n", 3, "Total parties N")
	flag.Parse()

	if *help {
		fmt.Println("Multi-party p2p chat + threshold signing (570 attempts) using libp2p")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  Listener:  ./thchat -sp 0 -t 2 -n 3")
		fmt.Println("  Dialers:   ./thchat -sp 0 -t 2 -n 3 -d <addr>[,<addr>...]")
		os.Exit(0)
	}

	var r io.Reader
	if *debug {
		r = mrand.New(mrand.NewSource(int64(*sourcePort)))
	} else {
		r = rand.Reader
	}

	h, err := makeHost(*sourcePort, r)
	if err != nil {
		log.Fatalf("makeHost error: %v", err)
	}
	defer func() { _ = h.Close() }()

	chat := NewChatNode(h)
	chat.N = *N
	chat.T = *Threshold

	h.SetStreamHandler(chatProto, chat.handleStream)
	printLocalInfo(h)

	if strings.TrimSpace(*dest) != "" {
		for _, d := range splitAddrs(*dest) {
			if err := chat.connectAndOpen(ctx, d); err != nil {
				log.Printf("connect failed for %q: %v", d, err)
			}
		}
	}

	go stdinBroadcastLoop(chat, h.ID())
	select {}
}

// Utilities functions
func makeHost(port int, randomness io.Reader) (host.Host, error) {
	prvKey, _, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, randomness)
	if err != nil {
		return nil, err
	}
	sourceMA, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port))
	return libp2p.New(
		libp2p.ListenAddrs(sourceMA),
		libp2p.Identity(prvKey),
	)
}

func stdinBroadcastLoop(c *ChatNode, self peer.ID) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("> ")
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("stdin read error: %v", err)
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) == 0 {
			continue
		}
		local := fmt.Sprintf("[%s] %s", shortID(self), line)
		fmt.Println(local)
		c.mu.RLock()
		for _, rw := range c.peers {
			_ = writeLine(rw, local)
		}
		c.mu.RUnlock()
	}
}

func splitAddrs(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func printLocalInfo(h host.Host) {
	fmt.Println("This node's multiaddresses:")
	for _, la := range h.Addrs() {
		fmt.Printf("  %s/p2p/%s\n", la, h.ID())
	}
	fmt.Println()
	fmt.Println("To connect here from another terminal:")
	for _, la := range h.Addrs() {
		if _, err := la.ValueForProtocol(multiaddr.P_TCP); err == nil {
			fmt.Printf("  ./thchat -sp 0 -d %s/p2p/%s\n", la, h.ID())
			break
		}
	}
	fmt.Println("Waiting for incoming connections…")
}

func writeLine(rw *bufio.ReadWriter, s string) error {
	if _, err := rw.WriteString(s + "\n"); err != nil {
		return err
	}
	return rw.Flush()
}

func shortID(id peer.ID) string {
	s := id.String()
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}
func shortIDStr(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}
