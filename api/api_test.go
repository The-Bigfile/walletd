package api_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.thebigfile.com/core/consensus"
	"go.thebigfile.com/core/types"
	"go.thebigfile.com/coreutils"
	"go.thebigfile.com/jape"
	"go.thebigfile.com/walletd/v2/api"
	"go.thebigfile.com/walletd/v2/internal/testutil"
	"go.thebigfile.com/walletd/v2/wallet"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"lukechampine.com/frand"
)

func startWalletServer(tb testing.TB, cn *testutil.ConsensusNode, log *zap.Logger, walletOpts ...wallet.Option) *api.Client {
	tb.Helper()

	l, err := net.Listen("tcp", ":0")
	if err != nil {
		tb.Fatal("failed to listen:", err)
	}
	tb.Cleanup(func() { l.Close() })

	wm, err := wallet.NewManager(cn.Chain, cn.Store, append([]wallet.Option{wallet.WithLogger(log.Named("wallet"))}, walletOpts...)...)
	if err != nil {
		tb.Fatal("failed to create wallet manager:", err)
	}
	tb.Cleanup(func() { wm.Close() })

	server := &http.Server{
		Handler:      api.NewServer(cn.Chain, cn.Syncer, wm, api.WithDebug(), api.WithLogger(log)),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	tb.Cleanup(func() { server.Close() })

	go server.Serve(l)
	return api.NewClient("http://"+l.Addr().String(), "password")
}

func TestWalletAdd(t *testing.T) {
	log := zaptest.NewLogger(t)

	n, genesisBlock := testutil.V1Network()
	giftPrivateKey := types.GeneratePrivateKey()
	giftAddress := types.StandardUnlockHash(giftPrivateKey.PublicKey())
	genesisBlock.Transactions[0].BigfileOutputs[0] = types.BigfileOutput{
		Value:   types.Bigfiles(1),
		Address: giftAddress,
	}
	cn := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cn, log)

	checkWalletResponse := func(wr api.WalletUpdateRequest, w wallet.Wallet, isUpdate bool) error {
		// check wallet
		if w.Name != wr.Name {
			return fmt.Errorf("expected wallet name to be %v, got %v", wr.Name, w.Name)
		} else if w.Description != wr.Description {
			return fmt.Errorf("expected wallet description to be %v, got %v", wr.Description, w.Description)
		} else if w.DateCreated.After(time.Now()) {
			return fmt.Errorf("expected wallet creation date to be in the past, got %v", w.DateCreated)
		} else if isUpdate && w.DateCreated == w.LastUpdated {
			return fmt.Errorf("expected wallet last updated date to be after creation %v, got %v", w.DateCreated, w.LastUpdated)
		}

		if wr.Metadata == nil && string(w.Metadata) == "null" { // zero value encodes as "null"
			return nil
		}

		// check metadata
		var am, bm map[string]any
		if err := json.Unmarshal(wr.Metadata, &am); err != nil {
			return fmt.Errorf("failed to unmarshal metadata a %q: %v", wr.Metadata, err)
		} else if err := json.Unmarshal(w.Metadata, &bm); err != nil {
			return fmt.Errorf("failed to unmarshal metadata b: %v", err)
		}

		if !reflect.DeepEqual(am, bm) { // not perfect, but probably enough for this test
			return fmt.Errorf("expected metadata to be equal %v, got %v", wr.Metadata, w.Metadata)
		}
		return nil
	}

	checkWallet := func(wa, wb wallet.Wallet) error {
		// check wallet
		if wa.Name != wb.Name {
			return fmt.Errorf("expected wallet name to be %v, got %v", wa.Name, wb.Name)
		} else if wa.Description != wb.Description {
			return fmt.Errorf("expected wallet description to be %v, got %v", wa.Description, wb.Description)
		} else if wa.DateCreated.Unix() != wb.DateCreated.Unix() {
			return fmt.Errorf("expected wallet creation date to be %v, got %v", wa.DateCreated, wb.DateCreated)
		} else if wa.LastUpdated.Unix() != wb.LastUpdated.Unix() {
			return fmt.Errorf("expected wallet last updated date to be %v, got %v", wa.LastUpdated, wb.LastUpdated)
		}

		if wa.Metadata == nil && string(wb.Metadata) == "null" { // zero value encodes as "null"
			return nil
		}

		// check metadata
		var am, bm map[string]any
		if err := json.Unmarshal(wa.Metadata, &am); err != nil {
			return fmt.Errorf("failed to unmarshal metadata a %q: %v", wa.Metadata, err)
		} else if err := json.Unmarshal(wb.Metadata, &bm); err != nil {
			return fmt.Errorf("failed to unmarshal metadata b %q: %v", wb.Metadata, err)
		}

		if !reflect.DeepEqual(am, bm) { // not perfect, but probably enough for this test
			return fmt.Errorf("expected metadata to be equal %v, got %v", wa.Metadata, wb.Metadata)
		}
		return nil
	}

	tests := []struct {
		Initial api.WalletUpdateRequest
		Update  api.WalletUpdateRequest
	}{
		{
			Initial: api.WalletUpdateRequest{Name: hex.EncodeToString(frand.Bytes(12))},
			Update:  api.WalletUpdateRequest{Name: hex.EncodeToString(frand.Bytes(12))},
		},
		{
			Initial: api.WalletUpdateRequest{Name: hex.EncodeToString(frand.Bytes(12)), Description: "hello, world!"},
			Update:  api.WalletUpdateRequest{Name: hex.EncodeToString(frand.Bytes(12)), Description: "goodbye, world!"},
		},
		{
			Initial: api.WalletUpdateRequest{Name: hex.EncodeToString(frand.Bytes(12)), Metadata: []byte(`{"foo": { "foo": "bar"}}`)},
			Update:  api.WalletUpdateRequest{Name: hex.EncodeToString(frand.Bytes(12)), Metadata: []byte(`{"foo": { "foo": "baz"}}`)},
		},
		{
			Initial: api.WalletUpdateRequest{Name: hex.EncodeToString(frand.Bytes(12)), Description: "hello, world!", Metadata: []byte(`{"foo": { "foo": "bar"}}`)},
			Update:  api.WalletUpdateRequest{Name: hex.EncodeToString(frand.Bytes(12)), Description: "goodbye, world!", Metadata: []byte(`{"foo": { "foo": "baz"}}`)},
		},
		{
			Initial: api.WalletUpdateRequest{Name: "constant name", Description: "constant description", Metadata: []byte(`{"foo": { "foo": "bar"}}`)},
			Update:  api.WalletUpdateRequest{Name: "constant name", Description: "constant description", Metadata: []byte(`{"foo": { "foo": "baz"}}`)},
		},
	}

	var expectedWallets []wallet.Wallet
	for i, test := range tests {
		w, err := c.AddWallet(test.Initial)
		if err != nil {
			t.Fatal(err)
		} else if err := checkWalletResponse(test.Initial, w, false); err != nil {
			t.Fatalf("test %v: %v", i, err)
		}

		expectedWallets = append(expectedWallets, w)
		// check that the wallet was added
		wallets, err := c.Wallets()
		if err != nil {
			t.Fatal(err)
		} else if len(wallets) != len(expectedWallets) {
			t.Fatalf("test %v: expected %v wallets, got %v", i, len(expectedWallets), len(wallets))
		}
		for j, w := range wallets {
			if err := checkWallet(expectedWallets[j], w); err != nil {
				t.Fatalf("test %v: wallet %v: %v", i, j, err)
			}
		}

		time.Sleep(time.Second) // ensure LastUpdated is different

		w, err = c.UpdateWallet(w.ID, test.Update)
		if err != nil {
			t.Fatal(err)
		} else if err := checkWalletResponse(test.Update, w, true); err != nil {
			t.Fatalf("test %v: %v", i, err)
		}

		// check that the wallet was updated
		expectedWallets[len(expectedWallets)-1] = w
		wallets, err = c.Wallets()
		if err != nil {
			t.Fatal(err)
		} else if len(wallets) != len(expectedWallets) {
			t.Fatalf("test %v: expected %v wallets, got %v", i, len(expectedWallets), len(wallets))
		}
		for j, w := range wallets {
			if err := checkWallet(expectedWallets[j], w); err != nil {
				t.Fatalf("test %v: wallet %v: %v", i, j, err)
			}
		}
	}
}

func TestWallet(t *testing.T) {
	log := zaptest.NewLogger(t)

	// create syncer
	syncerListener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer syncerListener.Close()

	// create chain manager
	n, genesisBlock := testutil.V1Network()
	giftPrivateKey := types.GeneratePrivateKey()
	giftAddress := types.StandardUnlockHash(giftPrivateKey.PublicKey())
	genesisBlock.Transactions[0].BigfileOutputs[0] = types.BigfileOutput{
		Value:   types.Bigfiles(1),
		Address: giftAddress,
	}
	cn := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cn, log)

	w, err := c.AddWallet(api.WalletUpdateRequest{Name: "primary"})
	if err != nil {
		t.Fatal(err)
	} else if w.Name != "primary" {
		t.Fatalf("expected wallet name to be 'primary', got %v", w.Name)
	}
	wc := c.Wallet(w.ID)
	if err := c.Rescan(0); err != nil {
		t.Fatal(err)
	}
	cn.WaitForSync(t)

	balance, err := wc.Balance()
	if err != nil {
		t.Fatal(err)
	} else if !balance.Bigfiles.IsZero() || !balance.ImmatureBigfiles.IsZero() || balance.Bigfunds != 0 {
		t.Fatal("balance should be 0")
	}

	// shouldn't have any events yet
	events, err := wc.Events(0, -1)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 0 {
		t.Fatal("event history should be empty")
	}

	// shouldn't have any addresses yet
	addresses, err := wc.Addresses()
	if err != nil {
		t.Fatal(err)
	} else if len(addresses) != 0 {
		t.Fatal("address list should be empty")
	}

	// create and add an address
	sk2 := types.GeneratePrivateKey()
	addr := types.StandardUnlockHash(sk2.PublicKey())
	err = wc.AddAddress(wallet.Address{
		Address: addr,
	})
	if err != nil {
		t.Fatal(err)
	}

	// should have an address now
	addresses, err = wc.Addresses()
	if err != nil {
		t.Fatal(err)
	} else if len(addresses) != 1 {
		t.Fatal("address list should have one address")
	} else if addresses[0].Address != addr {
		t.Fatalf("address should be %v, got %v", addr, addresses[0])
	}

	// send gift to wallet
	giftSCOID := genesisBlock.Transactions[0].BigfileOutputID(0)
	txn := types.Transaction{
		BigfileInputs: []types.BigfileInput{{
			ParentID:         giftSCOID,
			UnlockConditions: types.StandardUnlockConditions(giftPrivateKey.PublicKey()),
		}},
		BigfileOutputs: []types.BigfileOutput{
			{Address: addr, Value: types.Bigfiles(1).Div64(2)},
			{Address: addr, Value: types.Bigfiles(1).Div64(2)},
		},
		Signatures: []types.TransactionSignature{{
			ParentID:      types.Hash256(giftSCOID),
			CoveredFields: types.CoveredFields{WholeTransaction: true},
		}},
	}

	cs, err := c.ConsensusTipState()
	if err != nil {
		t.Fatal(err)
	}

	sig := giftPrivateKey.SignHash(cs.WholeSigHash(txn, types.Hash256(giftSCOID), 0, 0, nil))
	txn.Signatures[0].Signature = sig[:]

	// broadcast the transaction to the transaction pool
	if _, err := c.TxpoolBroadcast(cs.Index, []types.Transaction{txn}, nil); err != nil {
		t.Fatal(err)
	}

	// shouldn't have any events yet
	events, err = wc.Events(0, -1)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 0 {
		t.Fatal("event history should be empty")
	}

	unconfirmed, err := wc.UnconfirmedEvents()
	if err != nil {
		t.Fatal(err)
	} else if len(unconfirmed) != 1 {
		t.Fatal("txpool should have one transaction")
	}
	// confirm the transaction
	cn.MineBlocks(t, types.VoidAddress, 1)

	// get new balance
	balance, err = wc.Balance()
	if err != nil {
		t.Fatal(err)
	} else if !balance.Bigfiles.Equals(types.Bigfiles(1)) {
		t.Fatal("balance should be 1 BIG, got", balance.Bigfiles)
	} else if !balance.ImmatureBigfiles.IsZero() {
		t.Fatal("immature balance should be 0 BIG, got", balance.ImmatureBigfiles)
	}

	// transaction should appear in history
	events, err = wc.Events(0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) == 0 {
		t.Fatal("transaction should appear in history")
	}

	outputs, basis, err := wc.BigfileOutputs(0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(outputs) != 2 {
		t.Fatal("should have two UTXOs, got", len(outputs))
	} else if basis != cn.Chain.Tip() {
		t.Fatalf("basis should be %v, got %v", cn.Chain.Tip(), basis)
	} else if outputs[0].Confirmations != 1 {
		t.Fatalf("expected 1 confirmation, got %v", outputs[0].Confirmations)
	}

	// mine a block to add an immature balance
	expectedPayout := cn.Chain.TipState().BlockReward()
	cn.MineBlocks(t, addr, 1)

	// get new balance
	balance, err = wc.Balance()
	if err != nil {
		t.Fatal(err)
	} else if !balance.Bigfiles.Equals(types.Bigfiles(1)) {
		t.Fatal("balance should be 1 BIG, got", balance.Bigfiles)
	} else if !balance.ImmatureBigfiles.Equals(expectedPayout) {
		t.Fatalf("immature balance should be %d BIG, got %d BIG", expectedPayout, balance.ImmatureBigfiles)
	}

	// mine enough blocks for the miner payout to mature
	expectedBalance := types.Bigfiles(1).Add(expectedPayout)
	cn.MineBlocks(t, types.VoidAddress, int(n.MaturityDelay))

	// get new balance
	balance, err = wc.Balance()
	if err != nil {
		t.Fatal(err)
	} else if !balance.Bigfiles.Equals(expectedBalance) {
		t.Fatalf("balance should be %d, got %d", expectedBalance, balance.Bigfiles)
	} else if !balance.ImmatureBigfiles.IsZero() {
		t.Fatal("immature balance should be 0 BIG, got", balance.ImmatureBigfiles)
	}
}

func TestAddresses(t *testing.T) {
	log := zaptest.NewLogger(t)

	n, genesisBlock := testutil.V1Network()
	giftPrivateKey := types.GeneratePrivateKey()
	giftAddress := types.StandardUnlockHash(giftPrivateKey.PublicKey())
	genesisBlock.Transactions[0].BigfileOutputs[0] = types.BigfileOutput{
		Value:   types.Bigfiles(1),
		Address: giftAddress,
	}

	cn := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cn, log)

	sk2 := types.GeneratePrivateKey()
	addr := types.StandardUnlockHash(sk2.PublicKey())

	// personal index mode requires a wallet for indexing
	w, err := c.AddWallet(api.WalletUpdateRequest{Name: "primary"})
	if err != nil {
		t.Fatal(err)
	}
	wc := c.Wallet(w.ID)
	err = wc.AddAddress(wallet.Address{Address: addr})
	if err != nil {
		t.Fatal(err)
	}

	// send gift to wallet
	giftSCOID := genesisBlock.Transactions[0].BigfileOutputID(0)
	txn := types.Transaction{
		BigfileInputs: []types.BigfileInput{{
			ParentID:         giftSCOID,
			UnlockConditions: types.StandardUnlockConditions(giftPrivateKey.PublicKey()),
		}},
		BigfileOutputs: []types.BigfileOutput{
			{Address: addr, Value: types.Bigfiles(1).Div64(2)},
			{Address: addr, Value: types.Bigfiles(1).Div64(2)},
		},
		Signatures: []types.TransactionSignature{{
			ParentID:      types.Hash256(giftSCOID),
			CoveredFields: types.CoveredFields{WholeTransaction: true},
		}},
	}

	cs, err := c.ConsensusTipState()
	if err != nil {
		t.Fatal(err)
	}

	sig := giftPrivateKey.SignHash(cs.WholeSigHash(txn, types.Hash256(giftSCOID), 0, 0, nil))
	txn.Signatures[0].Signature = sig[:]

	// broadcast the transaction to the transaction pool
	if _, err := c.TxpoolBroadcast(cs.Index, []types.Transaction{txn}, nil); err != nil {
		t.Fatal(err)
	}
	cn.MineBlocks(t, types.VoidAddress, 1)

	// get new balance
	balance, err := c.AddressBalance(addr)
	if err != nil {
		t.Fatal(err)
	} else if !balance.Bigfiles.Equals(types.Bigfiles(1)) {
		t.Fatal("balance should be 1 BIG, got", balance.Bigfiles)
	} else if !balance.ImmatureBigfiles.IsZero() {
		t.Fatal("immature balance should be 0 BIG, got", balance.ImmatureBigfiles)
	}

	// transaction should appear in history
	events, err := c.AddressEvents(addr, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) == 0 {
		t.Fatal("transaction should appear in history")
	}

	outputs, basis, err := c.AddressBigfileOutputs(addr, false, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(outputs) != 2 {
		t.Fatal("should have two UTXOs, got", len(outputs))
	} else if basis != cn.Chain.Tip() {
		t.Fatalf("basis should be %v, got %v", cn.Chain.Tip(), basis)
	}

	// mine a block to add an immature balance
	expectedPayout := cn.Chain.TipState().BlockReward()
	cn.MineBlocks(t, addr, 1)

	// get new balance
	balance, err = c.AddressBalance(addr)
	if err != nil {
		t.Fatal(err)
	} else if !balance.Bigfiles.Equals(types.Bigfiles(1)) {
		t.Fatal("balance should be 1 BIG, got", balance.Bigfiles)
	} else if !balance.ImmatureBigfiles.Equals(expectedPayout) {
		t.Fatalf("immature balance should be %d BIG, got %d BIG", expectedPayout, balance.ImmatureBigfiles)
	}

	// mine enough blocks for the miner payout to mature
	expectedBalance := types.Bigfiles(1).Add(expectedPayout)
	cn.MineBlocks(t, types.VoidAddress, int(n.MaturityDelay))

	// get new balance
	balance, err = c.AddressBalance(addr)
	if err != nil {
		t.Fatal(err)
	} else if !balance.Bigfiles.Equals(expectedBalance) {
		t.Fatalf("balance should be %d, got %d", expectedBalance, balance.Bigfiles)
	} else if !balance.ImmatureBigfiles.IsZero() {
		t.Fatal("immature balance should be 0 BIG, got", balance.ImmatureBigfiles)
	}

	// create new wallet
	w, err = c.AddWallet(api.WalletUpdateRequest{Name: t.Name()})
	if err != nil {
		t.Fatal(err)
	}
	wc = c.Wallet(w.ID)

	// create two addresses
	pk1 := types.GeneratePrivateKey()
	pk2 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	// assert multiple addresses can be added to a wallet
	if err := wc.AddAddresses([]wallet.Address{{Address: addr1}, {Address: addr2}}); err != nil {
		t.Fatal(err)
	} else if addrs, err := wc.Addresses(); err != nil {
		t.Fatal(err)
	} else if len(addrs) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(addrs))
	}
}

func TestConsensus(t *testing.T) {
	log := zaptest.NewLogger(t)

	n, genesisBlock := testutil.V2Network()
	giftPrivateKey := types.GeneratePrivateKey()
	giftAddress := types.StandardUnlockHash(giftPrivateKey.PublicKey())
	genesisBlock.Transactions[0].BigfileOutputs[0] = types.BigfileOutput{
		Value:   types.Bigfiles(1),
		Address: giftAddress,
	}

	cn := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cn, log)

	// mine a block
	minedBlock, ok := coreutils.MineBlock(cn.Chain, types.Address{}, time.Minute)
	if !ok {
		t.Fatal("no block found")
	} else if err := cn.Chain.AddBlocks([]types.Block{minedBlock}); err != nil {
		t.Fatal(err)
	}

	// block should be tip now
	ci, err := c.ConsensusTip()
	if err != nil {
		t.Fatal(err)
	} else if ci.ID != minedBlock.ID() {
		t.Fatalf("expected consensus tip to be %v, got %v", minedBlock.ID(), ci.ID)
	}

	// fetch block
	b, err := c.ConsensusBlocksID(minedBlock.ID())
	if err != nil {
		t.Fatal(err)
	} else if b.ID() != minedBlock.ID() {
		t.Fatal("mismatch")
	}
}

func TestConsensusCheckpoint(t *testing.T) {
	log := zaptest.NewLogger(t)

	n, genesisBlock := testutil.V2Network()
	giftPrivateKey := types.GeneratePrivateKey()
	giftAddress := types.StandardUnlockHash(giftPrivateKey.PublicKey())
	genesisBlock.Transactions[0].BigfileOutputs[0] = types.BigfileOutput{
		Value:   types.Bigfiles(1),
		Address: giftAddress,
	}

	cn := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cn, log)

	// mine a block
	minedBlock, ok := coreutils.MineBlock(cn.Chain, types.Address{}, time.Minute)
	if !ok {
		t.Fatal("no block found")
	} else if err := cn.Chain.AddBlocks([]types.Block{minedBlock}); err != nil {
		t.Fatal(err)
	}

	// block should be tip now
	ci, err := c.ConsensusTip()
	if err != nil {
		t.Fatal(err)
	} else if ci.ID != minedBlock.ID() {
		t.Fatalf("expected consensus tip to be %v, got %v", minedBlock.ID(), ci.ID)
	}

	// fetch block
	resp, err := c.ConsensusCheckpointID(minedBlock.ID())
	if err != nil {
		t.Fatal(err)
	} else if resp.Block.ID() != minedBlock.ID() {
		t.Fatal("mismatch")
	} else if resp.State.Index != cn.Chain.Tip() {
		t.Fatal("mismatch tip")
	}

	heightResp, err := c.ConsensusCheckpointHeight(cn.Chain.Tip().Height)
	if err != nil {
		t.Fatal(err)
	} else if heightResp.Block.ID() != minedBlock.ID() {
		t.Fatal("mismatch")
	} else if heightResp.State.Index != cn.Chain.Tip() {
		t.Fatal("mismatch tip")
	}
}

func TestConsensusUpdates(t *testing.T) {
	log := zaptest.NewLogger(t)

	n, genesisBlock := testutil.V1Network()
	giftPrivateKey := types.GeneratePrivateKey()
	giftAddress := types.StandardUnlockHash(giftPrivateKey.PublicKey())
	genesisBlock.Transactions[0].BigfileOutputs[0] = types.BigfileOutput{
		Value:   types.Bigfiles(1),
		Address: giftAddress,
	}

	cn := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cn, log)
	cn.MineBlocks(t, types.VoidAddress, 10)

	reverted, applied, err := c.ConsensusUpdates(types.ChainIndex{}, 10)
	if err != nil {
		t.Fatal(err)
	} else if len(reverted) != 0 {
		t.Fatal("expected no reverted blocks")
	} else if len(applied) != 10 { // genesis + 10 mined blocks
		t.Fatalf("expected 10 applied blocks, got %v", len(applied))
	}

	for i, cau := range applied {
		// using i for height since we're testing the update contents
		expected, ok := cn.Chain.BestIndex(uint64(i))
		if !ok {
			t.Fatalf("failed to get expected index for block %v", i)
		} else if cau.State.Index != expected {
			t.Fatalf("expected index %v, got %v", expected, cau.State.Index)
		} else if cau.State.Network.Name != n.Name { // TODO: better comparison. reflect.DeepEqual is failing in CI, but passing local.
			t.Fatalf("expected network to be %q, got %q", n.Name, cau.State.Network.Name)
		}
	}
}

func TestConstructBigfiles(t *testing.T) {
	log := zaptest.NewLogger(t)

	n, genesisBlock := testutil.V1Network()
	senderPrivateKey := types.GeneratePrivateKey()
	senderPolicy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(senderPrivateKey.PublicKey()))}
	senderAddr := senderPolicy.Address()

	receiverPrivateKey := types.GeneratePrivateKey()
	receiverPolicy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(receiverPrivateKey.PublicKey()))}
	receiverAddr := receiverPolicy.Address()

	genesisBlock.Transactions[0].BigfileOutputs[0] = types.BigfileOutput{
		Value:   types.Bigfiles(100),
		Address: senderAddr,
	}

	cn := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cn, log)

	w, err := c.AddWallet(api.WalletUpdateRequest{
		Name: "primary",
	})
	if err != nil {
		t.Fatal(err)
	}

	wc := c.Wallet(w.ID)
	// add an address with no spend policy
	err = wc.AddAddress(wallet.Address{
		Address: senderAddr,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Rescan(0); err != nil {
		t.Fatal(err)
	}
	cn.MineBlocks(t, types.VoidAddress, 1)

	// try to construct a valid transaction with no spend policy
	_, err = wc.Construct([]types.BigfileOutput{
		{Value: types.Bigfiles(1), Address: receiverAddr},
	}, nil, senderAddr)
	if !strings.Contains(err.Error(), "no spend policy") {
		t.Fatalf("expected error to contain %q, got %q", "no spend policy", err)
	}

	// add the spend policy
	err = wc.AddAddress(wallet.Address{
		Address: senderAddr,
		SpendPolicy: &types.SpendPolicy{
			Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(senderPrivateKey.PublicKey())),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// try to construct a transaction with more bigfunds than the wallet holds.
	// this will lock all of the wallet's bigfiles
	resp, err := wc.Construct([]types.BigfileOutput{
		{Value: types.Bigfiles(1), Address: receiverAddr},
	}, []types.BigfundOutput{
		{Value: 100000, Address: senderAddr},
	}, senderAddr)
	if !strings.Contains(err.Error(), "insufficient funds") {
		t.Fatal(err)
	}

	// construct a transaction with a single bigfile output
	// this will fail if the utxos were not unlocked
	resp, err = wc.Construct([]types.BigfileOutput{
		{Value: types.Bigfiles(1), Address: receiverAddr},
	}, nil, senderAddr)
	if err != nil {
		t.Fatal(err)
	}

	switch {
	case resp.Transaction.BigfileOutputs[0].Address != receiverAddr:
		t.Fatalf("expected transaction to have output address %q, got %q", receiverAddr, resp.Transaction.BigfileOutputs[0].Address)
	case !resp.Transaction.BigfileOutputs[0].Value.Equals(types.Bigfiles(1)):
		t.Fatalf("expected transaction to have output value of %v, got %v", types.Bigfiles(1), resp.Transaction.BigfileOutputs[0].Value)
	case resp.Transaction.BigfileOutputs[1].Address != senderAddr:
		t.Fatalf("expected transaction to have change address %q, got %q", senderAddr, resp.Transaction.BigfileOutputs[1].Address)
	case !resp.Transaction.BigfileOutputs[1].Value.Equals(types.Bigfiles(99).Sub(resp.EstimatedFee)):
		t.Fatalf("expected transaction to have change value of %v, got %v", types.Bigfiles(99).Sub(resp.EstimatedFee), resp.Transaction.BigfileOutputs[1].Value)
	}

	cs, err := c.ConsensusTipState()
	if err != nil {
		t.Fatal(err)
	}

	// sign the transaction
	for i, sig := range resp.Transaction.Signatures {
		sigHash := cs.WholeSigHash(resp.Transaction, sig.ParentID, 0, 0, nil)
		sig := senderPrivateKey.SignHash(sigHash)
		resp.Transaction.Signatures[i].Signature = sig[:]
	}

	if broadcastResp, err := c.TxpoolBroadcast(resp.Basis, []types.Transaction{resp.Transaction}, nil); err != nil {
		t.Fatal(err)
	} else if len(broadcastResp.Transactions) != 1 || len(broadcastResp.V2Transactions) != 0 {
		t.Fatalf("expected 1 v1 ID and 0 v2 IDs, got %v and %v", len(broadcastResp.Transactions), len(broadcastResp.V2Transactions))
	} else if broadcastResp.Transactions[0].ID() != resp.ID {
		t.Fatalf("expected v1 ID to be %v, got %v", resp.ID, broadcastResp.Transactions[0].ID())
	}

	unconfirmed, err := wc.UnconfirmedEvents()
	if err != nil {
		t.Fatal(err)
	} else if len(unconfirmed) != 1 {
		t.Fatalf("expected 1 unconfirmed event, got %v", len(unconfirmed))
	}
	expectedValue := types.Bigfiles(1).Add(resp.EstimatedFee)
	sent := unconfirmed[0]
	switch {
	case types.TransactionID(sent.ID) != resp.ID:
		t.Fatalf("expected unconfirmed event to have transaction ID %q, got %q", resp.ID, sent.ID)
	case sent.Type != wallet.EventTypeV1Transaction:
		t.Fatalf("expected unconfirmed event to have type %q, got %q", wallet.EventTypeV1Transaction, sent.Type)
	case !sent.BigfileOutflow().Sub(sent.BigfileInflow()).Equals(expectedValue):
		t.Fatalf("expected unconfirmed event to have outflow of %v, got %v", expectedValue, sent.BigfileOutflow().Sub(sent.BigfileInflow()))
	}
	cn.MineBlocks(t, types.VoidAddress, 1)

	confirmed, err := wc.Events(0, 5)
	if err != nil {
		t.Fatal(err)
	} else if len(confirmed) != 2 {
		t.Fatalf("expected 2 confirmed events, got %v", len(confirmed)) // initial gift + sent transaction
	}
	sent = confirmed[0]
	switch {
	case types.TransactionID(sent.ID) != resp.ID:
		t.Fatalf("expected confirmed event to have transaction ID %q, got %q", resp.ID, sent.ID)
	case sent.Type != wallet.EventTypeV1Transaction:
		t.Fatalf("expected confirmed event to have type %q, got %q", wallet.EventTypeV1Transaction, sent.Type)
	case !sent.BigfileOutflow().Sub(sent.BigfileInflow()).Equals(expectedValue):
		t.Fatalf("expected confirmed event to have outflow of %v, got %v", expectedValue, sent.BigfileOutflow().Sub(sent.BigfileInflow()))
	}
}

func TestConstructBigfunds(t *testing.T) {
	log := zaptest.NewLogger(t)

	n, genesisBlock := testutil.V1Network()
	senderPrivateKey := types.GeneratePrivateKey()
	senderPolicy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(senderPrivateKey.PublicKey()))}
	senderAddr := senderPolicy.Address()

	receiverPrivateKey := types.GeneratePrivateKey()
	receiverPolicy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(receiverPrivateKey.PublicKey()))}
	receiverAddr := receiverPolicy.Address()

	genesisBlock.Transactions[0].BigfileOutputs[0] = types.BigfileOutput{
		Value:   types.Bigfiles(100),
		Address: senderAddr,
	}
	genesisBlock.Transactions[0].BigfundOutputs[0].Address = senderAddr

	cn := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cn, log)

	w, err := c.AddWallet(api.WalletUpdateRequest{
		Name: "primary",
	})
	if err != nil {
		t.Fatal(err)
	}

	wc := c.Wallet(w.ID)
	err = wc.AddAddress(wallet.Address{
		Address:     senderAddr,
		SpendPolicy: &senderPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Rescan(0); err != nil {
		t.Fatal(err)
	}
	cn.MineBlocks(t, types.VoidAddress, 1)

	resp, err := wc.Construct(nil, []types.BigfundOutput{
		{Value: 1, Address: receiverAddr},
	}, senderAddr)
	if err != nil {
		t.Fatal(err)
	}

	switch {
	case resp.Transaction.BigfileOutputs[0].Address != senderAddr:
		t.Fatalf("expected transaction to have change address %q, got %q", senderAddr, resp.Transaction.BigfileOutputs[0].Address)
	case !resp.Transaction.BigfileOutputs[0].Value.Equals(types.Bigfiles(100).Sub(resp.EstimatedFee)):
		t.Fatalf("expected transaction to have change value of %v, got %v", types.Bigfiles(99).Sub(resp.EstimatedFee), resp.Transaction.BigfileOutputs[0].Value)
	case resp.Transaction.BigfundOutputs[0].Address != receiverAddr:
		t.Fatalf("expected transaction to have output address %q, got %q", receiverAddr, resp.Transaction.BigfundOutputs[0].Address)
	case resp.Transaction.BigfundOutputs[0].Value != 1:
		t.Fatalf("expected transaction to have output value of %v, got %v", types.Bigfiles(1), resp.Transaction.BigfundOutputs[0].Value)
	case resp.Transaction.BigfundOutputs[1].Address != senderAddr:
		t.Fatalf("expected transaction to have change address %q, got %q", senderAddr, resp.Transaction.BigfundOutputs[1].Address)
	case resp.Transaction.BigfundOutputs[1].Value != 9999:
		t.Fatalf("expected transaction to have change value of %v, got %v", types.Bigfiles(99).Sub(resp.EstimatedFee), resp.Transaction.BigfundOutputs[1].Value)
	case resp.Transaction.BigfundInputs[0].ClaimAddress != senderAddr:
		t.Fatalf("expected transaction to have bigfund input claim address %q, got %q", senderAddr, resp.Transaction.BigfundInputs[0].ClaimAddress)
	}

	cs, err := c.ConsensusTipState()
	if err != nil {
		t.Fatal(err)
	}

	// sign the transaction
	for i, sig := range resp.Transaction.Signatures {
		sigHash := cs.WholeSigHash(resp.Transaction, sig.ParentID, 0, 0, nil)
		sig := senderPrivateKey.SignHash(sigHash)
		resp.Transaction.Signatures[i].Signature = sig[:]
	}

	if _, err := c.TxpoolBroadcast(resp.Basis, []types.Transaction{resp.Transaction}, nil); err != nil {
		t.Fatal(err)
	}

	unconfirmed, err := wc.UnconfirmedEvents()
	if err != nil {
		t.Fatal(err)
	} else if len(unconfirmed) != 1 {
		t.Fatalf("expected 1 unconfirmed event, got %v", len(unconfirmed))
	}
	sent := unconfirmed[0]
	switch {
	case types.TransactionID(sent.ID) != resp.ID:
		t.Fatalf("expected unconfirmed event to have transaction ID %q, got %q", resp.ID, sent.ID)
	case sent.Type != wallet.EventTypeV1Transaction:
		t.Fatalf("expected unconfirmed event to have type %q, got %q", wallet.EventTypeV1Transaction, sent.Type)
	case !sent.BigfileOutflow().Sub(sent.BigfileInflow()).Equals(resp.EstimatedFee):
		t.Fatalf("expected unconfirmed event to have outflow of %v, got %v", resp.EstimatedFee, sent.BigfileOutflow().Sub(sent.BigfileInflow()))
	case sent.BigfundOutflow()-sent.BigfundInflow() != 1:
		t.Fatalf("expected unconfirmed event to have bigfund outflow of 1, got %v", sent.BigfundOutflow()-sent.BigfundInflow())
	}
	cn.MineBlocks(t, types.VoidAddress, 1)

	confirmed, err := wc.Events(0, 5)
	if err != nil {
		t.Fatal(err)
	} else if len(confirmed) != 2 {
		t.Fatalf("expected 2 confirmed events, got %v", len(confirmed)) // initial gift + sent transaction
	}
	sent = confirmed[0]
	switch {
	case types.TransactionID(sent.ID) != resp.ID:
		t.Fatalf("expected unconfirmed event to have transaction ID %q, got %q", resp.ID, sent.ID)
	case sent.Type != wallet.EventTypeV1Transaction:
		t.Fatalf("expected unconfirmed event to have type %q, got %q", wallet.EventTypeV1Transaction, sent.Type)
	case !sent.BigfileOutflow().Sub(sent.BigfileInflow()).Equals(resp.EstimatedFee):
		t.Fatalf("expected unconfirmed event to have outflow of %v, got %v", resp.EstimatedFee, sent.BigfileOutflow().Sub(sent.BigfileInflow()))
	case sent.BigfundOutflow()-sent.BigfundInflow() != 1:
		t.Fatalf("expected unconfirmed event to have bigfund outflow of 1, got %v", sent.BigfundOutflow()-sent.BigfundInflow())
	}
}

func TestConstructV2Bigfiles(t *testing.T) {
	log := zaptest.NewLogger(t)

	n, genesisBlock := testutil.V2Network()
	senderPrivateKey := types.GeneratePrivateKey()
	senderPolicy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(senderPrivateKey.PublicKey()))}
	senderAddr := senderPolicy.Address()

	receiverPrivateKey := types.GeneratePrivateKey()
	receiverPolicy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(receiverPrivateKey.PublicKey()))}
	receiverAddr := receiverPolicy.Address()

	genesisBlock.Transactions[0].BigfileOutputs[0] = types.BigfileOutput{
		Value:   types.Bigfiles(100),
		Address: senderAddr,
	}

	cm := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cm, log)

	w, err := c.AddWallet(api.WalletUpdateRequest{
		Name: "primary",
	})
	if err != nil {
		t.Fatal(err)
	}

	wc := c.Wallet(w.ID)
	// add an address without a spend policy
	err = wc.AddAddress(wallet.Address{
		Address: senderAddr,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Rescan(0); err != nil {
		t.Fatal(err)
	}
	cm.MineBlocks(t, types.VoidAddress, 1)

	// try to construct a transaction
	resp, err := wc.ConstructV2([]types.BigfileOutput{
		{Value: types.Bigfiles(1), Address: receiverAddr},
	}, nil, senderAddr)
	if !strings.Contains(err.Error(), "no spend policy") {
		t.Fatalf("expected spend policy error, got %q", err)
	}

	// add a spend policy to the address
	err = wc.AddAddress(wallet.Address{
		Address:     senderAddr,
		SpendPolicy: &senderPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}

	// try to construct a transaction with more bigfunds than the wallet holds.
	// this will lock all of the wallet's Bigfile UTXOs
	resp, err = wc.ConstructV2([]types.BigfileOutput{
		{Value: types.Bigfiles(1), Address: receiverAddr},
	}, []types.BigfundOutput{
		{Value: 100000, Address: senderAddr},
	}, senderAddr)
	if !strings.Contains(err.Error(), "insufficient funds") {
		t.Fatal(err)
	}

	// this will fail if the utxos were not properly
	// unlocked when the previous request failed
	resp, err = wc.ConstructV2([]types.BigfileOutput{
		{Value: types.Bigfiles(1), Address: receiverAddr},
	}, nil, senderAddr)
	if err != nil {
		t.Fatal(err)
	}

	cs, err := c.ConsensusTipState()
	if err != nil {
		t.Fatal(err)
	}

	switch {
	case resp.Transaction.BigfileOutputs[0].Address != receiverAddr:
		t.Fatalf("expected transaction to have output address %q, got %q", receiverAddr, resp.Transaction.BigfileOutputs[0].Address)
	case !resp.Transaction.BigfileOutputs[0].Value.Equals(types.Bigfiles(1)):
		t.Fatalf("expected transaction to have output value of %v, got %v", types.Bigfiles(1), resp.Transaction.BigfileOutputs[0].Value)
	case resp.Transaction.BigfileOutputs[1].Address != senderAddr:
		t.Fatalf("expected transaction to have change address %q, got %q", senderAddr, resp.Transaction.BigfileOutputs[1].Address)
	case !resp.Transaction.BigfileOutputs[1].Value.Equals(types.Bigfiles(99).Sub(resp.EstimatedFee)):
		t.Fatalf("expected transaction to have change value of %v, got %v", types.Bigfiles(99).Sub(resp.EstimatedFee), resp.Transaction.BigfileOutputs[1].Value)
	}

	// sign the transaction
	sigHash := cs.InputSigHash(resp.Transaction)
	for i := range resp.Transaction.BigfileInputs {
		sig := senderPrivateKey.SignHash(sigHash)
		resp.Transaction.BigfileInputs[i].SatisfiedPolicy.Signatures = []types.Signature{sig}
	}

	if broadcastResp, err := c.TxpoolBroadcast(resp.Basis, nil, []types.V2Transaction{resp.Transaction}); err != nil {
		t.Fatal(err)
	} else if len(broadcastResp.Transactions) != 0 || len(broadcastResp.V2Transactions) != 1 {
		t.Fatalf("expected 1 v1 ID and 0 v2 IDs, got %v and %v", len(broadcastResp.Transactions), len(broadcastResp.V2Transactions))
	} else if broadcastResp.V2Transactions[0].ID() != resp.ID {
		t.Fatalf("expected v2 ID to be %v, got %v", resp.ID, broadcastResp.V2Transactions[0].ID())
	}

	unconfirmed, err := wc.UnconfirmedEvents()
	if err != nil {
		t.Fatal(err)
	} else if len(unconfirmed) != 1 {
		t.Fatalf("expected 1 unconfirmed event, got %v", len(unconfirmed))
	}
	expectedValue := types.Bigfiles(1).Add(resp.EstimatedFee)
	sent := unconfirmed[0]
	switch {
	case types.TransactionID(sent.ID) != resp.ID:
		t.Fatalf("expected unconfirmed event to have transaction ID %q, got %q", resp.ID, sent.ID)
	case sent.Type != wallet.EventTypeV2Transaction:
		t.Fatalf("expected unconfirmed event to have type %q, got %q", wallet.EventTypeV2Transaction, sent.Type)
	case !sent.BigfileOutflow().Sub(sent.BigfileInflow()).Equals(expectedValue):
		t.Fatalf("expected unconfirmed event to have outflow of %v, got %v", expectedValue, sent.BigfileOutflow().Sub(sent.BigfileInflow()))
	}

	unconfirmed, err = c.TPoolEvents()
	if err != nil {
		t.Fatal(err)
	} else if len(unconfirmed) != 1 {
		t.Fatalf("expected 1 unconfirmed event, got %v", len(unconfirmed))
	} else if unconfirmed[0].Type != wallet.EventTypeV2Transaction {
		t.Fatalf("expected unconfirmed event to have type %q, got %q", wallet.EventTypeV2Transaction, unconfirmed[0].Type)
	} else if unconfirmed[0].ID != sent.ID {
		t.Fatalf("expected unconfirmed event to have ID %q, got %q", sent.ID, unconfirmed[0].ID)
	}

	cm.MineBlocks(t, types.VoidAddress, 1)

	confirmed, err := wc.Events(0, 5)
	if err != nil {
		t.Fatal(err)
	} else if len(confirmed) != 2 {
		t.Fatalf("expected 2 confirmed events, got %v", len(confirmed)) // initial gift + sent transaction
	}
	sent = confirmed[0]
	switch {
	case types.TransactionID(sent.ID) != resp.ID:
		t.Fatalf("expected confirmed event to have transaction ID %q, got %q", resp.ID, sent.ID)
	case sent.Type != wallet.EventTypeV2Transaction:
		t.Fatalf("expected confirmed event to have type %q, got %q", wallet.EventTypeV2Transaction, sent.Type)
	case !sent.BigfileOutflow().Sub(sent.BigfileInflow()).Equals(expectedValue):
		t.Fatalf("expected confirmed event to have outflow of %v, got %v", expectedValue, sent.BigfileOutflow().Sub(sent.BigfileInflow()))
	}
}

func TestConstructV2Bigfunds(t *testing.T) {
	log := zaptest.NewLogger(t)

	n, genesisBlock := testutil.V2Network()
	senderPrivateKey := types.GeneratePrivateKey()
	senderPolicy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(senderPrivateKey.PublicKey()))}
	senderAddr := senderPolicy.Address()

	receiverPrivateKey := types.GeneratePrivateKey()
	receiverPolicy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(receiverPrivateKey.PublicKey()))}
	receiverAddr := receiverPolicy.Address()

	genesisBlock.Transactions[0].BigfileOutputs[0] = types.BigfileOutput{
		Value:   types.Bigfiles(100),
		Address: senderAddr,
	}
	genesisBlock.Transactions[0].BigfundOutputs[0].Address = senderAddr

	cn := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cn, log)

	w, err := c.AddWallet(api.WalletUpdateRequest{
		Name: "primary",
	})
	if err != nil {
		t.Fatal(err)
	}

	wc := c.Wallet(w.ID)
	err = wc.AddAddress(wallet.Address{
		Address:     senderAddr,
		SpendPolicy: &senderPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Rescan(0); err != nil {
		t.Fatal(err)
	}
	cn.MineBlocks(t, types.VoidAddress, 1)

	resp, err := wc.ConstructV2(nil, []types.BigfundOutput{
		{Value: 1, Address: receiverAddr},
	}, senderAddr)
	if err != nil {
		t.Fatal(err)
	}

	cs, err := c.ConsensusTipState()
	if err != nil {
		t.Fatal(err)
	}

	// sign the transaction
	sigHash := cs.InputSigHash(resp.Transaction)
	sig := senderPrivateKey.SignHash(sigHash)
	for i := range resp.Transaction.BigfundInputs {
		resp.Transaction.BigfundInputs[i].SatisfiedPolicy.Signatures = []types.Signature{sig}
	}
	for i := range resp.Transaction.BigfundInputs {
		resp.Transaction.BigfileInputs[i].SatisfiedPolicy.Signatures = []types.Signature{sig}
	}

	if _, err := c.TxpoolBroadcast(resp.Basis, nil, []types.V2Transaction{resp.Transaction}); err != nil {
		t.Fatal(err)
	}

	unconfirmed, err := wc.UnconfirmedEvents()
	if err != nil {
		t.Fatal(err)
	} else if len(unconfirmed) != 1 {
		t.Fatalf("expected 1 unconfirmed event, got %v", len(unconfirmed))
	}
	sent := unconfirmed[0]
	switch {
	case types.TransactionID(sent.ID) != resp.ID:
		t.Fatalf("expected unconfirmed event to have transaction ID %q, got %q", resp.ID, sent.ID)
	case sent.Type != wallet.EventTypeV2Transaction:
		t.Fatalf("expected unconfirmed event to have type %q, got %q", wallet.EventTypeV2Transaction, sent.Type)
	case !sent.BigfileOutflow().Sub(sent.BigfileInflow()).Equals(resp.EstimatedFee):
		t.Fatalf("expected unconfirmed event to have outflow of %v, got %v", resp.EstimatedFee, sent.BigfileOutflow().Sub(sent.BigfileInflow()))
	case sent.BigfundOutflow()-sent.BigfundInflow() != 1:
		t.Fatalf("expected unconfirmed event to have bigfund outflow of 1, got %v", sent.BigfundOutflow()-sent.BigfundInflow())
	}
	cn.MineBlocks(t, types.VoidAddress, 1)

	confirmed, err := wc.Events(0, 5)
	if err != nil {
		t.Fatal(err)
	} else if len(confirmed) != 2 {
		t.Fatalf("expected 2 confirmed events, got %v", len(confirmed)) // initial gift + sent transaction
	}

	sent = confirmed[0]
	switch {
	case types.TransactionID(sent.ID) != resp.ID:
		t.Fatalf("expected unconfirmed event to have transaction ID %q, got %q", resp.ID, sent.ID)
	case sent.Type != wallet.EventTypeV2Transaction:
		t.Fatalf("expected unconfirmed event to have type %q, got %q", wallet.EventTypeV2Transaction, sent.Type)
	case !sent.BigfileOutflow().Sub(sent.BigfileInflow()).Equals(resp.EstimatedFee):
		t.Fatalf("expected unconfirmed event to have outflow of %v, got %v", resp.EstimatedFee, sent.BigfileOutflow().Sub(sent.BigfileInflow()))
	case sent.BigfundOutflow()-sent.BigfundInflow() != 1:
		t.Fatalf("expected unconfirmed event to have bigfund outflow of 1, got %v", sent.BigfundOutflow()-sent.BigfundInflow())
	}
}

func TestSpentElement(t *testing.T) {
	log := zaptest.NewLogger(t)

	n, genesisBlock := testutil.V2Network()
	senderPrivateKey := types.GeneratePrivateKey()
	senderPolicy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(senderPrivateKey.PublicKey()))}
	senderAddr := senderPolicy.Address()

	receiverPrivateKey := types.GeneratePrivateKey()
	receiverPolicy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(receiverPrivateKey.PublicKey()))}
	receiverAddr := receiverPolicy.Address()

	genesisBlock.Transactions[0].BigfileOutputs[0] = types.BigfileOutput{
		Value:   types.Bigfiles(100),
		Address: senderAddr,
	}
	genesisBlock.Transactions[0].BigfundOutputs[0].Address = senderAddr

	cn := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cn, log, wallet.WithIndexMode(wallet.IndexModeFull))

	// trigger initial scan
	cn.MineBlocks(t, types.VoidAddress, 1)

	bige, basis, err := c.AddressBigfileOutputs(senderAddr, false, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(bige) != 1 {
		t.Fatalf("expected 1 bigfile element, got %v", len(bige))
	}

	// check if the element is spent
	spent, err := c.SpentBigfileElement(bige[0].ID)
	if err != nil {
		t.Fatal(err)
	} else if spent.Spent {
		t.Fatal("expected bigfile element to be unspent")
	} else if spent.Event != nil {
		t.Fatalf("expected bigfile element to have no event, got %v", spent.Event)
	}

	// spend the element
	txn := types.V2Transaction{
		BigfileInputs: []types.V2BigfileInput{
			{
				Parent: bige[0].BigfileElement,
				SatisfiedPolicy: types.SatisfiedPolicy{
					Policy: senderPolicy,
				},
			},
		},
		BigfileOutputs: []types.BigfileOutput{
			{
				Value:   bige[0].BigfileOutput.Value,
				Address: receiverAddr,
			},
		},
	}
	cs, err := c.ConsensusTipState()
	if err != nil {
		t.Fatal(err)
	}
	txn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{
		senderPrivateKey.SignHash(cs.InputSigHash(txn)),
	}

	if _, err := c.TxpoolBroadcast(basis, nil, []types.V2Transaction{txn}); err != nil {
		t.Fatal(err)
	}
	cn.MineBlocks(t, types.VoidAddress, 1)

	// check if the element is spent
	spent, err = c.SpentBigfileElement(bige[0].ID)
	if err != nil {
		t.Fatal(err)
	} else if !spent.Spent {
		t.Fatal("expected bigfile element to be spent")
	} else if types.TransactionID(spent.Event.ID) != txn.ID() {
		t.Fatalf("expected bigfile element to have event %q, got %q", txn.ID(), spent.Event.ID)
	} else if spent.Event.Type != wallet.EventTypeV2Transaction {
		t.Fatalf("expected bigfile element to have type %q, got %q", wallet.EventTypeV2Transaction, spent.Event.Type)
	}

	// mine until the utxo is pruned
	cn.MineBlocks(t, types.VoidAddress, 144)

	_, err = c.SpentBigfileElement(bige[0].ID)
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected error to contain %q, got %q", "not found", err)
	}

	bfe, basis, err := c.AddressBigfundOutputs(senderAddr, false, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(bfe) != 1 {
		t.Fatalf("expected 1 bigfund element, got %v", len(bfe))
	}

	// check if the bigfund element is spent
	spent, err = c.SpentBigfundElement(bfe[0].ID)
	if err != nil {
		t.Fatal(err)
	} else if spent.Spent {
		t.Fatal("expected bigfund element to be unspent")
	} else if spent.Event != nil {
		t.Fatalf("expected bigfund element to have no event, got %v", spent.Event)
	}

	// spend the element
	txn = types.V2Transaction{
		BigfundInputs: []types.V2BigfundInput{
			{
				Parent: bfe[0].BigfundElement,
				SatisfiedPolicy: types.SatisfiedPolicy{
					Policy: senderPolicy,
				},
				ClaimAddress: senderAddr,
			},
		},
		BigfundOutputs: []types.BigfundOutput{
			{
				Address: receiverAddr,
				Value:   bfe[0].BigfundOutput.Value,
			},
		},
	}
	cs, err = c.ConsensusTipState()
	if err != nil {
		t.Fatal(err)
	}
	txn.BigfundInputs[0].SatisfiedPolicy.Signatures = []types.Signature{
		senderPrivateKey.SignHash(cs.InputSigHash(txn)),
	}

	if _, err := c.TxpoolBroadcast(basis, nil, []types.V2Transaction{txn}); err != nil {
		t.Fatal(err)
	}
	cn.MineBlocks(t, types.VoidAddress, 1)

	// check if the element is spent
	spent, err = c.SpentBigfundElement(bfe[0].ID)
	if err != nil {
		t.Fatal(err)
	} else if !spent.Spent {
		t.Fatal("expected bigfund element to be spent")
	} else if types.TransactionID(spent.Event.ID) != txn.ID() {
		t.Fatalf("expected bigfund element to have event %q, got %q", txn.ID(), spent.Event.ID)
	} else if spent.Event.Type != wallet.EventTypeV2Transaction {
		t.Fatalf("expected bigfund element to have type %q, got %q", wallet.EventTypeV2Transaction, spent.Event.Type)
	}

	// mine until the utxo is pruned
	cn.MineBlocks(t, types.VoidAddress, 144)

	_, err = c.SpentBigfundElement(bfe[0].ID)
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected error to contain %q, got %q", "not found", err)
	}
}

func TestDebugMine(t *testing.T) {
	log := zaptest.NewLogger(t)
	n, genesisBlock := testutil.V1Network()

	cn := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cn, log)

	jc := jape.Client{
		BaseURL:  c.BaseURL(),
		Password: "password",
	}

	err := jc.POST(context.Background(), "/debug/mine", api.DebugMineRequest{
		Blocks:  5,
		Address: types.VoidAddress,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cn.WaitForSync(t)

	tip, err := c.ConsensusTip()
	if err != nil {
		t.Fatal(err)
	} else if tip.Height != 5 {
		t.Fatalf("expected tip height to be 5, got %v", tip.Height)
	}
}

func TestAPISecurity(t *testing.T) {
	n, genesisBlock := testutil.V1Network()
	log := zaptest.NewLogger(t)

	cn := testutil.NewConsensusNode(t, n, genesisBlock, log)
	wm, err := wallet.NewManager(cn.Chain, cn.Store, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	httpListener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal("failed to listen:", err)
	}
	defer httpListener.Close()

	server := &http.Server{
		Handler:      api.NewServer(cn.Chain, cn.Syncer, wm, api.WithDebug(), api.WithLogger(zaptest.NewLogger(t)), api.WithBasicAuth("test")),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	defer server.Close()
	go server.Serve(httpListener)

	replaceHandler := func(apiOpts ...api.ServerOption) {
		server.Handler = api.NewServer(cn.Chain, cn.Syncer, wm, apiOpts...)
	}

	// create a client with correct credentials
	c := api.NewClient("http://"+httpListener.Addr().String(), "test")
	if _, err := c.ConsensusTip(); err != nil {
		t.Fatal(err)
	}

	// create a client with incorrect credentials
	c = api.NewClient("http://"+httpListener.Addr().String(), "wrong")
	if _, err := c.ConsensusTip(); err == nil {
		t.Fatal("expected auth error")
	} else if err.Error() != "unauthorized" {
		t.Fatal("expected auth error, got", err)
	}

	// replace the handler with a new one that doesn't require auth
	replaceHandler()

	// create a client without credentials
	c = api.NewClient("http://"+httpListener.Addr().String(), "")
	if _, err := c.ConsensusTip(); err != nil {
		t.Fatal(err)
	}

	// create a client with incorrect credentials
	c = api.NewClient("http://"+httpListener.Addr().String(), "test")
	if _, err := c.ConsensusTip(); err != nil {
		t.Fatal(err)
	}

	// replace the handler with one that requires auth and has public endpoints
	replaceHandler(api.WithBasicAuth("test"), api.WithPublicEndpoints(true))

	// create a client without credentials
	c = api.NewClient("http://"+httpListener.Addr().String(), "")

	// check that a public endpoint is accessible
	if _, err := c.ConsensusTip(); err != nil {
		t.Fatal(err)
	}

	// check that a private endpoint is still protected
	if _, err := c.Wallets(); err == nil {
		t.Fatal("expected auth error")
	} else if err.Error() != "unauthorized" {
		t.Fatal("expected auth error, got", err)
	}

	// create a client with credentials
	c = api.NewClient("http://"+httpListener.Addr().String(), "test")

	// check that both public and private endpoints are accessible
	if _, err := c.Wallets(); err != nil {
		t.Fatal(err)
	} else if _, err := c.ConsensusTip(); err != nil {
		t.Fatal(err)
	}
}

func TestAPINoContent(t *testing.T) {
	log := zaptest.NewLogger(t)
	n, genesisBlock := testutil.V1Network()

	cn := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cn, log)

	buf, err := json.Marshal(cn.Chain.Tip().Height)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, c.BaseURL()+"/rescan", bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected status %v, got %v", http.StatusNoContent, resp.StatusCode)
	} else if resp.ContentLength != 0 {
		t.Fatalf("expected no content, got %v bytes", resp.ContentLength)
	}
}

func TestV2TransactionUpdateBasis(t *testing.T) {
	log := zaptest.NewLogger(t)
	n, genesisBlock := testutil.V2Network()

	cn := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cn, log)

	// create a wallet
	w, err := c.AddWallet(api.WalletUpdateRequest{
		Name: "primary",
	})
	if err != nil {
		t.Fatal(err)
	}

	wc := c.Wallet(w.ID)

	pk := types.GeneratePrivateKey()
	policy := types.SpendPolicy{Type: types.PolicyTypePublicKey(pk.PublicKey())}
	addr := policy.Address()

	err = wc.AddAddress(wallet.Address{
		Address:     addr,
		SpendPolicy: &policy,
	})
	if err != nil {
		t.Fatal(err)
	}

	// fund the wallet
	cn.MineBlocks(t, addr, 5+int(n.MaturityDelay))

	resp, err := wc.ConstructV2([]types.BigfileOutput{
		{Value: types.Bigfiles(100), Address: addr},
	}, nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	parentTxn, basis := resp.Transaction, resp.Basis

	// sign the transaction
	cs, err := c.ConsensusTipState()
	if err != nil {
		t.Fatal(err)
	}
	sigHash := cs.InputSigHash(parentTxn)
	sig := pk.SignHash(sigHash)
	for i := range parentTxn.BigfileInputs {
		parentTxn.BigfileInputs[i].SatisfiedPolicy.Signatures = []types.Signature{sig}
	}

	// broadcast the transaction
	if _, err := c.TxpoolBroadcast(basis, nil, []types.V2Transaction{parentTxn}); err != nil {
		t.Fatal(err)
	}
	cn.MineBlocks(t, types.VoidAddress, 1)

	// create a child transaction
	bige := parentTxn.EphemeralBigfileOutput(0)
	childTxn := types.V2Transaction{
		BigfileInputs: []types.V2BigfileInput{
			{
				Parent: bige,
				SatisfiedPolicy: types.SatisfiedPolicy{
					Policy: policy,
				},
			},
		},
		BigfileOutputs: []types.BigfileOutput{
			{Address: types.VoidAddress, Value: bige.BigfileOutput.Value},
		},
	}
	childSigHash := cs.InputSigHash(childTxn)
	childTxn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(childSigHash)}

	txnset := []types.V2Transaction{parentTxn, childTxn}

	tip, err := c.ConsensusTip()
	if err != nil {
		t.Fatal(err)
	}

	basis, txnset, err = c.V2UpdateTransactionSetBasis(txnset, basis, tip)
	if err != nil {
		t.Fatal(err)
	} else if len(txnset) != 1 {
		t.Fatalf("expected 1 transactions, got %v", len(txnset))
	} else if txnset[0].ID() != childTxn.ID() {
		t.Fatalf("expected parent transaction to be removed")
	} else if basis != tip {
		t.Fatalf("expected basis to be %v, got %v", tip, basis)
	}

	if _, err := c.TxpoolBroadcast(basis, nil, txnset); err != nil {
		t.Fatal(err)
	}
	cn.MineBlocks(t, types.VoidAddress, 1)
}

func TestAddressTPool(t *testing.T) {
	log := zaptest.NewLogger(t)

	pk := types.GeneratePrivateKey()
	uc := types.StandardUnlockConditions(pk.PublicKey())
	addr1 := types.StandardUnlockHash(pk.PublicKey())

	n, genesisBlock := testutil.V2Network()
	genesisBlock.Transactions[0].BigfileOutputs[0] = types.BigfileOutput{
		Value:   types.Bigfiles(100),
		Address: addr1,
	}

	cn := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cn, log, wallet.WithIndexMode(wallet.IndexModeFull))

	assertBigfileElement := func(t *testing.T, id types.BigfileOutputID, value types.Currency, confirmations uint64) {
		t.Helper()

		utxos, _, err := c.AddressBigfileOutputs(addr1, true, 0, 1)
		if err != nil {
			t.Fatal(err)
		}
		for _, bige := range utxos {
			if bige.ID == id {
				if !bige.BigfileOutput.Value.Equals(value) {
					t.Fatalf("expected value %v, got %v", value, bige.BigfileOutput.Value)
				} else if bige.Confirmations != confirmations {
					t.Fatalf("expected confirmations %d, got %d", confirmations, bige.Confirmations)
				}
				return
			}
		}
		t.Fatalf("expected bigfile element with ID %q not found", id)
	}

	cn.MineBlocks(t, types.VoidAddress, 1)

	airdropID := genesisBlock.Transactions[0].BigfileOutputID(0)
	assertBigfileElement(t, airdropID, types.Bigfiles(100), 2)

	utxos, basis, err := c.AddressBigfileOutputs(addr1, true, 0, 100)
	if err != nil {
		t.Fatal(err)
	}

	cs, err := c.ConsensusTipState()
	if err != nil {
		t.Fatal(err)
	}
	txn := types.V2Transaction{
		BigfileInputs: []types.V2BigfileInput{
			{
				Parent: utxos[0].BigfileElement,
				SatisfiedPolicy: types.SatisfiedPolicy{
					Policy: types.SpendPolicy{
						Type: types.PolicyTypeUnlockConditions(uc),
					},
				},
			},
		},
		BigfileOutputs: []types.BigfileOutput{
			{
				Address: types.VoidAddress,
				Value:   types.Bigfiles(25),
			},
			{
				Address: addr1,
				Value:   types.Bigfiles(75),
			},
		},
	}
	sigHash := cs.InputSigHash(txn)
	txn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{
		pk.SignHash(sigHash),
	}

	if _, err := c.TxpoolBroadcast(basis, nil, []types.V2Transaction{txn}); err != nil {
		t.Fatal(err)
	}

	assertBigfileElement(t, txn.BigfileOutputID(txn.ID(), 1), types.Bigfiles(75), 0)
	cn.MineBlocks(t, types.VoidAddress, 1)
	assertBigfileElement(t, txn.BigfileOutputID(txn.ID(), 1), types.Bigfiles(75), 1)
}

func TestEphemeralTransactions(t *testing.T) {
	log := zaptest.NewLogger(t)
	pk := types.GeneratePrivateKey()
	sp := types.SpendPolicy{
		Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk.PublicKey())),
	}
	addr1 := sp.Address()

	n, genesisBlock := testutil.V2Network()
	genesisBlock.Transactions[0].BigfileOutputs[0] = types.BigfileOutput{
		Value:   types.Bigfiles(100),
		Address: addr1,
	}

	cn := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cn, log, wallet.WithIndexMode(wallet.IndexModeFull))

	cn.MineBlocks(t, types.VoidAddress, 1)

	biges, basis, err := c.AddressBigfileOutputs(addr1, true, 0, 100)
	if err != nil {
		t.Fatal(err)
	}

	txn := types.V2Transaction{
		BigfileInputs: []types.V2BigfileInput{

			{
				Parent: biges[0].BigfileElement,
				SatisfiedPolicy: types.SatisfiedPolicy{
					Policy: sp,
				},
			},
		},
		BigfileOutputs: []types.BigfileOutput{
			{
				Address: types.VoidAddress,
				Value:   types.Bigfiles(50),
			},
			{
				Address: addr1,
				Value:   types.Bigfiles(50),
			},
		},
	}
	cs, err := c.ConsensusTipState()
	if err != nil {
		t.Fatal(err)
	}
	sigHash := cs.InputSigHash(txn)
	txn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(sigHash)}
	expectedOutputID := txn.BigfileOutputID(txn.ID(), 1)

	if _, err := c.TxpoolBroadcast(basis, nil, []types.V2Transaction{txn}); err != nil {
		t.Fatal(err)
	}

	biges, basis, err = c.AddressBigfileOutputs(addr1, true, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(biges) != 1 {
		t.Fatalf("expected 1 bigfile element, got %v", len(biges))
	} else if biges[0].ID != expectedOutputID {
		t.Fatalf("expected bigfile element ID %q, got %q", expectedOutputID, biges[0].ID)
	} else if biges[0].StateElement.LeafIndex != types.UnassignedLeafIndex {
		t.Fatalf("expected bigfile element to have unassigned leaf index, got %v", biges[0].StateElement.LeafIndex)
	}

	txn2 := types.V2Transaction{
		BigfileInputs: []types.V2BigfileInput{
			{
				Parent: biges[0].BigfileElement,
				SatisfiedPolicy: types.SatisfiedPolicy{
					Policy: sp,
				},
			},
		},
		BigfileOutputs: []types.BigfileOutput{
			{
				Address: types.VoidAddress,
				Value:   biges[0].BigfileOutput.Value,
			},
		},
	}
	sigHash = cs.InputSigHash(txn2)
	txn2.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(sigHash)}

	// mine a block so the basis is behind
	cn.MineBlocks(t, types.VoidAddress, 1)

	biges, _, err = c.AddressBigfileOutputs(addr1, true, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(biges) != 1 {
		t.Fatalf("expected no bigfile elements, got %v", len(biges))
	} else if biges[0].ID != expectedOutputID {
		t.Fatalf("expected bigfile element ID %q, got %q", expectedOutputID, biges[0].ID)
	} else if biges[0].StateElement.LeafIndex == types.UnassignedLeafIndex {
		t.Fatalf("expected bigfile element to have leaf index, got %v", biges[0].StateElement.LeafIndex)
	}

	if _, err := c.TxpoolBroadcast(basis, nil, []types.V2Transaction{txn2}); err != nil {
		t.Fatal(err)
	}

	biges, _, err = c.AddressBigfileOutputs(addr1, true, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(biges) != 0 {
		t.Fatalf("expected no bigfile elements, got %v", len(biges))
	}
}

func TestBroadcastRace(t *testing.T) {
	t.Skip("NDF") // TODO: fix

	log := zap.NewNop()
	pk := types.GeneratePrivateKey()
	sp := types.SpendPolicy{
		Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk.PublicKey())),
	}
	addr1 := sp.Address()

	n, genesisBlock := testutil.V2Network()
	genesisBlock.Transactions[0].BigfileOutputs[0] = types.BigfileOutput{
		Value:   types.Bigfiles(100000),
		Address: addr1,
	}

	cn := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cn, log, wallet.WithIndexMode(wallet.IndexModeFull))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				cn.MineBlocks(t, types.VoidAddress, 1)
			}
		}
	}()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for i := 0; i < 100; i++ {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			biges, basis, err := c.AddressBigfileOutputs(addr1, true, 0, 100)
			if err != nil {
				panic(err)
			}

			burn := types.Bigfiles(1)
			rem := biges[0].BigfileOutput.Value.Sub(burn)
			txn := types.V2Transaction{
				BigfileInputs: []types.V2BigfileInput{
					{
						Parent: biges[0].BigfileElement,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: sp,
						},
					},
				},
				BigfileOutputs: []types.BigfileOutput{
					{
						Address: types.VoidAddress,
						Value:   burn,
					},
					{
						Address: addr1,
						Value:   rem,
					},
				},
			}
			cs, err := c.ConsensusTipState()
			if err != nil {
				t.Fatal(err)
			}
			sigHash := cs.InputSigHash(txn)
			txn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(sigHash)}
			if _, err := c.TxpoolBroadcast(basis, nil, []types.V2Transaction{txn}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestTxPoolOverwriteProofs(t *testing.T) {
	log := zaptest.NewLogger(t)

	n, genesisBlock := testutil.V2Network()
	senderPrivateKey := types.GeneratePrivateKey()
	senderPolicy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(senderPrivateKey.PublicKey()))}
	senderAddr := senderPolicy.Address()

	receiverPrivateKey := types.GeneratePrivateKey()
	receiverPolicy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(receiverPrivateKey.PublicKey()))}
	receiverAddr := receiverPolicy.Address()

	genesisBlock.Transactions[0].BigfileOutputs[0] = types.BigfileOutput{
		Value:   types.Bigfiles(100),
		Address: senderAddr,
	}

	cm := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cm, log, wallet.WithIndexMode(wallet.IndexModeFull))

	w, err := c.AddWallet(api.WalletUpdateRequest{
		Name: "primary",
	})
	if err != nil {
		t.Fatal(err)
	}

	wc := c.Wallet(w.ID)
	// add an address
	err = wc.AddAddress(wallet.Address{
		Address:     senderAddr,
		SpendPolicy: &senderPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	cm.MineBlocks(t, types.VoidAddress, 1)

	resp, err := wc.ConstructV2([]types.BigfileOutput{
		{Value: types.Bigfiles(1), Address: receiverAddr},
	}, nil, senderAddr)
	if err != nil {
		t.Fatal(err)
	}

	cs, err := c.ConsensusTipState()
	if err != nil {
		t.Fatal(err)
	}

	// sign the transaction
	sigHash := cs.InputSigHash(resp.Transaction)
	for i := range resp.Transaction.BigfileInputs {
		resp.Transaction.BigfileInputs[i].SatisfiedPolicy.Signatures = []types.Signature{senderPrivateKey.SignHash(sigHash)}
	}

	// assert the transaction is valid
	cs, ok := cm.Chain.State(resp.Basis.ID)
	if !ok {
		t.Fatal("failed to get state")
	}
	ms := consensus.NewMidState(cs)
	if err := consensus.ValidateV2Transaction(ms, resp.Transaction); err != nil {
		t.Fatal(err)
	}

	// corrupt the proof
	resp.Transaction.BigfileInputs[0].Parent.StateElement.MerkleProof[frand.Intn(len(resp.Transaction.BigfileInputs[0].Parent.StateElement.MerkleProof))] = frand.Entropy256()

	// assert the transaction is invalid
	ms = consensus.NewMidState(cs)
	if err := consensus.ValidateV2Transaction(ms, resp.Transaction); !strings.Contains(err.Error(), "not present in the accumulator") {
		t.Fatalf("expected error to contain %q, got %v", "not present in the accumulator", err)
	}

	if broadcastResp, err := c.TxpoolBroadcast(resp.Basis, nil, []types.V2Transaction{resp.Transaction}); err != nil {
		t.Fatal(err)
	} else if len(broadcastResp.Transactions) != 0 || len(broadcastResp.V2Transactions) != 1 {
		t.Fatalf("expected 1 v1 ID and 0 v2 IDs, got %v and %v", len(broadcastResp.Transactions), len(broadcastResp.V2Transactions))
	} else if broadcastResp.V2Transactions[0].ID() != resp.ID {
		t.Fatalf("expected v2 ID to be %v, got %v", resp.ID, broadcastResp.V2Transactions[0].ID())
	}

	unconfirmed, err := wc.UnconfirmedEvents()
	if err != nil {
		t.Fatal(err)
	} else if len(unconfirmed) != 1 {
		t.Fatalf("expected 1 unconfirmed event, got %v", len(unconfirmed))
	}
	expectedValue := types.Bigfiles(1).Add(resp.EstimatedFee)
	sent := unconfirmed[0]
	switch {
	case types.TransactionID(sent.ID) != resp.ID:
		t.Fatalf("expected unconfirmed event to have transaction ID %q, got %q", resp.ID, sent.ID)
	case sent.Type != wallet.EventTypeV2Transaction:
		t.Fatalf("expected unconfirmed event to have type %q, got %q", wallet.EventTypeV2Transaction, sent.Type)
	case !sent.BigfileOutflow().Sub(sent.BigfileInflow()).Equals(expectedValue):
		t.Fatalf("expected unconfirmed event to have outflow of %v, got %v", expectedValue, sent.BigfileOutflow().Sub(sent.BigfileInflow()))
	}
	cm.MineBlocks(t, types.VoidAddress, 1)

	confirmed, err := wc.Events(0, 5)
	if err != nil {
		t.Fatal(err)
	} else if len(confirmed) != 2 {
		t.Fatalf("expected 2 confirmed events, got %v", len(confirmed)) // initial gift + sent transaction
	}
	sent = confirmed[0]
	switch {
	case types.TransactionID(sent.ID) != resp.ID:
		t.Fatalf("expected confirmed event to have transaction ID %q, got %q", resp.ID, sent.ID)
	case sent.Type != wallet.EventTypeV2Transaction:
		t.Fatalf("expected confirmed event to have type %q, got %q", wallet.EventTypeV2Transaction, sent.Type)
	case !sent.BigfileOutflow().Sub(sent.BigfileInflow()).Equals(expectedValue):
		t.Fatalf("expected confirmed event to have outflow of %v, got %v", expectedValue, sent.BigfileOutflow().Sub(sent.BigfileInflow()))
	}
}

func TestTxPoolOverwriteProofsEphemeral(t *testing.T) {
	log := zaptest.NewLogger(t)

	n, genesisBlock := testutil.V2Network()
	senderPrivateKey := types.GeneratePrivateKey()
	senderPolicy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(senderPrivateKey.PublicKey()))}
	senderAddr := senderPolicy.Address()

	receiverPrivateKey := types.GeneratePrivateKey()
	receiverPolicy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(receiverPrivateKey.PublicKey()))}
	receiverAddr := receiverPolicy.Address()

	genesisBlock.Transactions[0].BigfileOutputs[0] = types.BigfileOutput{
		Value:   types.Bigfiles(100),
		Address: senderAddr,
	}

	cm := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cm, log, wallet.WithIndexMode(wallet.IndexModeFull))

	w, err := c.AddWallet(api.WalletUpdateRequest{
		Name: "primary",
	})
	if err != nil {
		t.Fatal(err)
	}

	wc := c.Wallet(w.ID)
	// add an address
	err = wc.AddAddress(wallet.Address{
		Address:     senderAddr,
		SpendPolicy: &senderPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	cm.MineBlocks(t, types.VoidAddress, 1)

	resp, err := wc.ConstructV2([]types.BigfileOutput{
		{Value: types.Bigfiles(1), Address: senderAddr},
	}, nil, senderAddr)
	if err != nil {
		t.Fatal(err)
	}

	cs, err := c.ConsensusTipState()
	if err != nil {
		t.Fatal(err)
	}

	// sign the transaction
	sigHash := cs.InputSigHash(resp.Transaction)
	for i := range resp.Transaction.BigfileInputs {
		resp.Transaction.BigfileInputs[i].SatisfiedPolicy.Signatures = []types.Signature{senderPrivateKey.SignHash(sigHash)}
	}

	basis := resp.Basis
	txnset := []types.V2Transaction{resp.Transaction, {
		BigfileInputs: []types.V2BigfileInput{
			{
				Parent: resp.Transaction.EphemeralBigfileOutput(0),
				SatisfiedPolicy: types.SatisfiedPolicy{
					Policy: senderPolicy,
				},
			},
		},
		BigfileOutputs: []types.BigfileOutput{
			{Address: receiverAddr, Value: types.Bigfiles(1)},
		},
	}}
	sigHash = cs.InputSigHash(txnset[1])
	for i := range txnset[1].BigfileInputs {
		txnset[1].BigfileInputs[i].SatisfiedPolicy.Signatures = []types.Signature{senderPrivateKey.SignHash(sigHash)}
	}

	// corrupt the proof
	txnset[0].BigfileInputs[0].Parent.StateElement.MerkleProof[frand.Intn(len(resp.Transaction.BigfileInputs[0].Parent.StateElement.MerkleProof))] = frand.Entropy256()

	if broadcastResp, err := c.TxpoolBroadcast(basis, nil, txnset); err != nil {
		t.Fatal(err)
	} else if len(broadcastResp.Transactions) != 0 || len(broadcastResp.V2Transactions) != 2 {
		t.Fatalf("expected 0 v1 ID and 2 v2 IDs, got %v and %v", len(broadcastResp.Transactions), len(broadcastResp.V2Transactions))
	} else if broadcastResp.V2Transactions[0].ID() != txnset[0].ID() {
		t.Fatalf("expected v2 ID to be %v, got %v", txnset[0].ID(), broadcastResp.V2Transactions[0].ID())
	} else if broadcastResp.V2Transactions[1].ID() != txnset[1].ID() {
		t.Fatalf("expected v2 ID to be %v, got %v", txnset[1].ID(), broadcastResp.V2Transactions[1].ID())
	}

	unconfirmed, err := wc.UnconfirmedEvents()
	if err != nil {
		t.Fatal(err)
	} else if len(unconfirmed) != 2 {
		t.Fatalf("expected 2 unconfirmed events, got %v", len(unconfirmed))
	}
	cm.MineBlocks(t, types.VoidAddress, 1)

	confirmed, err := wc.Events(0, 5)
	if err != nil {
		t.Fatal(err)
	} else if len(confirmed) != 3 {
		t.Fatalf("expected 3 confirmed events, got %v", len(confirmed)) // initial gift + setup + sent
	}
}

func TestWalletConfirmations(t *testing.T) {
	log := zaptest.NewLogger(t)

	// create syncer
	syncerListener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer syncerListener.Close()

	// create chain manager
	n, genesisBlock := testutil.V1Network()
	giftPrivateKey := types.GeneratePrivateKey()
	giftAddress := types.StandardUnlockHash(giftPrivateKey.PublicKey())
	genesisBlock.Transactions[0].BigfileOutputs[0] = types.BigfileOutput{
		Value:   types.Bigfiles(1),
		Address: giftAddress,
	}
	genesisBlock.Transactions[0].BigfundOutputs[0].Address = giftAddress

	cn := testutil.NewConsensusNode(t, n, genesisBlock, log)
	c := startWalletServer(t, cn, log)

	w, err := c.AddWallet(api.WalletUpdateRequest{
		Name: "primary",
	})
	if err != nil {
		t.Fatal(err)
	}
	wc := c.Wallet(w.ID)

	// create and add an address
	sk2 := types.GeneratePrivateKey()
	addr := types.StandardUnlockHash(sk2.PublicKey())
	err = wc.AddAddress(wallet.Address{
		Address: addr,
		SpendPolicy: &types.SpendPolicy{
			Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(sk2.PublicKey())),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Rescan(0)

	// send gift to wallet
	giftSCOID := genesisBlock.Transactions[0].BigfileOutputID(0)
	txn := types.Transaction{
		BigfileInputs: []types.BigfileInput{{
			ParentID:         giftSCOID,
			UnlockConditions: types.StandardUnlockConditions(giftPrivateKey.PublicKey()),
		}},
		BigfileOutputs: []types.BigfileOutput{
			{Address: addr, Value: types.Bigfiles(1)},
		},
		BigfundInputs: []types.BigfundInput{{
			ParentID:         genesisBlock.Transactions[0].BigfundOutputID(0),
			UnlockConditions: types.StandardUnlockConditions(giftPrivateKey.PublicKey()),
		}},
		BigfundOutputs: []types.BigfundOutput{
			{Address: addr, Value: genesisBlock.Transactions[0].BigfundOutputs[0].Value},
		},
		Signatures: []types.TransactionSignature{{
			ParentID:      types.Hash256(giftSCOID),
			CoveredFields: types.CoveredFields{WholeTransaction: true},
		}, {
			ParentID:      types.Hash256(genesisBlock.Transactions[0].BigfundOutputID(0)),
			CoveredFields: types.CoveredFields{WholeTransaction: true},
		}},
	}

	cs, err := c.ConsensusTipState()
	if err != nil {
		t.Fatal(err)
	}

	sig := giftPrivateKey.SignHash(cs.WholeSigHash(txn, types.Hash256(giftSCOID), 0, 0, nil))
	txn.Signatures[0].Signature = sig[:]
	sig2 := giftPrivateKey.SignHash(cs.WholeSigHash(txn, types.Hash256(genesisBlock.Transactions[0].BigfundOutputID(0)), 0, 0, nil))
	txn.Signatures[1].Signature = sig2[:]

	// broadcast the transaction to the transaction pool
	if _, err := c.TxpoolBroadcast(cs.Index, []types.Transaction{txn}, nil); err != nil {
		t.Fatal(err)
	}

	// confirm the transaction
	cn.MineBlocks(t, types.VoidAddress, 1)

	assertConfirmations := func(t *testing.T, n uint64) {
		t.Helper()

		outputs, basis, err := wc.BigfileOutputs(0, 100)
		if err != nil {
			t.Fatal(err)
		} else if len(outputs) != 1 {
			t.Fatal("should have one UTXOs, got", len(outputs))
		} else if basis != cn.Chain.Tip() {
			t.Fatalf("basis should be %v, got %v", cn.Chain.Tip(), basis)
		} else if outputs[0].Confirmations != n {
			t.Fatalf("expected %d confirmation, got %v", n, outputs[0].Confirmations)
		}

		bfe, basis, err := wc.BigfundOutputs(0, 100)
		if err != nil {
			t.Fatal(err)
		} else if len(bfe) != 1 {
			t.Fatal("should have one bigfund output, got", len(bfe))
		} else if basis != cn.Chain.Tip() {
			t.Fatalf("basis should be %v, got %v", cn.Chain.Tip(), basis)
		} else if bfe[0].Confirmations != n {
			t.Fatalf("expected %d confirmation, got %v", n, bfe[0].Confirmations)
		}
	}

	assertConfirmations(t, 1)
	cn.MineBlocks(t, types.VoidAddress, 10)
	assertConfirmations(t, 11)
}
