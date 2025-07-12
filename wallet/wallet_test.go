package wallet_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"go.thebigfile.com/core/consensus"
	"go.thebigfile.com/core/types"
	"go.thebigfile.com/coreutils"
	"go.thebigfile.com/coreutils/chain"
	"go.thebigfile.com/coreutils/testutil"
	"go.thebigfile.com/walletd/v2/persist/sqlite"
	"go.thebigfile.com/walletd/v2/wallet"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"lukechampine.com/frand"
)

func waitForBlock(tb testing.TB, cm *chain.Manager, ws wallet.Store) {
	tb.Helper()
	for i := 0; i < 1000; i++ {
		time.Sleep(10 * time.Millisecond)
		tip, _ := ws.LastCommittedIndex()
		if tip == cm.Tip() {
			return
		}
	}
	tb.Fatal("timed out waiting for block")
}

func mineAndSync(tb testing.TB, cm *chain.Manager, ws wallet.Store, addr types.Address, n int) {
	tb.Helper()

	for i := 0; i < n; i++ {
		testutil.MineBlocks(tb, cm, addr, 1)
		waitForBlock(tb, cm, ws)
	}
}

func testV1Network(bigfundAddr types.Address) (*consensus.Network, types.Block) {
	// use a modified version of Zen
	n, genesisBlock := chain.TestnetZen()
	genesisBlock.Transactions[0].BigfundOutputs[0].Address = bigfundAddr
	n.InitialTarget = types.BlockID{0xFF}
	n.HardforkDevAddr.Height = 1
	n.HardforkTax.Height = 1
	n.HardforkStorageProof.Height = 1
	n.HardforkOak.Height = 1
	n.HardforkASIC.Height = 1
	n.HardforkFoundation.Height = 1
	n.HardforkV2.AllowHeight = 1000
	n.HardforkV2.RequireHeight = 1000
	return n, genesisBlock
}

func testV2Network(bigfundAddr types.Address) (*consensus.Network, types.Block) {
	// use a modified version of Zen
	n, genesisBlock := chain.TestnetZen()
	genesisBlock.Transactions[0].BigfundOutputs[0].Address = bigfundAddr
	n.InitialTarget = types.BlockID{0xFF}
	n.HardforkDevAddr.Height = 1
	n.HardforkTax.Height = 1
	n.HardforkStorageProof.Height = 1
	n.HardforkOak.Height = 1
	n.HardforkASIC.Height = 1
	n.HardforkFoundation.Height = 1
	n.HardforkV2.AllowHeight = 100
	n.HardforkV2.RequireHeight = 110
	return n, genesisBlock
}

func mineBlock(state consensus.State, txns []types.Transaction, minerAddr types.Address) types.Block {
	b := types.Block{
		ParentID:     state.Index.ID,
		Timestamp:    types.CurrentTimestamp(),
		Transactions: txns,
		MinerPayouts: []types.BigfileOutput{{Address: minerAddr, Value: state.BlockReward()}},
	}
	for b.ID().CmpWork(state.ChildTarget) < 0 {
		b.Nonce += state.NonceFactor()
	}
	return b
}

func mineV2Block(state consensus.State, txns []types.V2Transaction, minerAddr types.Address) types.Block {
	b := types.Block{
		ParentID:     state.Index.ID,
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.BigfileOutput{{Address: minerAddr, Value: state.BlockReward()}},

		V2: &types.V2BlockData{
			Transactions: txns,
			Height:       state.Index.Height + 1,
		},
	}
	b.V2.Commitment = state.Commitment(b.MinerPayouts[0].Address, b.Transactions, b.V2Transactions())
	for b.ID().CmpWork(state.ChildTarget) < 0 {
		b.Nonce += state.NonceFactor()
	}
	return b
}

func TestReserve(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	network, genesisBlock := testutil.V2Network()
	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}
	cm := chain.NewManager(store, genesisState)

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")), wallet.WithLockDuration(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	w, err := wm.AddWallet(wallet.Wallet{Name: "test"})
	if err != nil {
		t.Fatal(err)
	}

	sk := types.GeneratePrivateKey()
	sp := types.SpendPolicy{Type: types.PolicyTypePublicKey(sk.PublicKey())}
	addr := sp.Address()

	err = wm.AddAddresses(w.ID, wallet.Address{
		Address:     addr,
		SpendPolicy: &sp,
	})
	if err != nil {
		t.Fatal(err)
	}

	scoID := types.Hash256(frand.Entropy256())
	if err := wm.Reserve([]types.Hash256{scoID}); err != nil {
		t.Fatal(err)
	}

	// output should be locked
	if err := wm.Reserve([]types.Hash256{scoID}); !errors.Is(err, wallet.ErrAlreadyReserved) {
		t.Fatalf("expected output locked error, got %v", err)
	}

	time.Sleep(3 * time.Second)

	// output should be unlocked
	if err := wm.Reserve([]types.Hash256{scoID}); err != nil {
		t.Fatal(err)
	}

	// output should be locked
	if err := wm.Reserve([]types.Hash256{scoID}); !errors.Is(err, wallet.ErrAlreadyReserved) {
		t.Fatalf("expected output locked error, got %v", err)
	}

	wm.Release([]types.Hash256{scoID})
	// output should be unlocked
	if err := wm.Reserve([]types.Hash256{scoID}); err != nil {
		t.Fatal(err)
	}
}

func TestSelectBigfiles(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	network, genesisBlock := testutil.Network()
	network.InitialCoinbase = types.Bigfiles(100)
	network.MinimumCoinbase = types.Bigfiles(100)

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}
	cm := chain.NewManager(store, genesisState)

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	w, err := wm.AddWallet(wallet.Wallet{Name: "test"})
	if err != nil {
		t.Fatal(err)
	}

	sk := types.GeneratePrivateKey()
	uc := types.UnlockConditions{
		PublicKeys:         []types.UnlockKey{sk.PublicKey().UnlockKey()},
		SignaturesRequired: 1,
	}
	addr := uc.UnlockHash()

	err = wm.AddAddresses(w.ID, wallet.Address{
		Address: addr,
		SpendPolicy: &types.SpendPolicy{
			Type: types.PolicyTypeUnlockConditions(uc),
		},
	})
	if err != nil {
		t.Fatal(err)
	} else if err := wm.Scan(context.Background(), types.ChainIndex{}); err != nil {
		t.Fatal(err)
	}

	mineAndSync := func(t *testing.T, addr types.Address, n int) {
		t.Helper()

		for i := 0; i < n; i++ {
			testutil.MineBlocks(t, cm, addr, 1)
			waitForBlock(t, cm, db)
		}
	}
	// mine enough utxos to ensure the pagination works
	mineAndSync(t, addr, 200)
	// mine until all the wallet's outputs are mature
	mineAndSync(t, types.VoidAddress, int(cm.TipState().Network.MaturityDelay))

	// check that the wallet has 200 matured outputs
	utxos, _, err := wm.UnspentBigfileOutputs(w.ID, 0, 1000)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 200 {
		t.Fatalf("expected 200 outputs, got %v", len(utxos))
	}

	balance, err := wm.WalletBalance(w.ID)
	if err != nil {
		t.Fatal(err)
	}

	// fund a transaction with more than the wallet balance
	_, _, _, err = wm.SelectBigfileElements(w.ID, balance.Bigfiles.Add(types.Bigfiles(1)), false)
	if !errors.Is(err, wallet.ErrInsufficientFunds) {
		t.Fatal("expected insufficient funds error")
	}

	// fund multiple overlapping transactions to ensure no double spends
	var selected []types.Hash256
	seen := make(map[types.BigfileOutputID]bool)
	for i := 0; i < len(utxos); i++ {
		utxos, _, change, err := wm.SelectBigfileElements(w.ID, types.Bigfiles(1), false)
		if err != nil {
			t.Fatal(err)
		} else if len(utxos) != 1 { // one UTXO should always be enough to cover
			t.Fatalf("expected 1 output, got %v", len(utxos))
		} else if seen[utxos[0].ID] {
			t.Fatalf("double spend %v", utxos[0].ID)
		} else if !change.Equals(types.Bigfiles(99)) {
			t.Fatalf("expected 99 BIG change, got %v", change)
		}
		seen[utxos[0].ID] = true
		selected = append(selected, types.Hash256(utxos[0].ID))
	}

	// all available outputs should be locked
	_, _, _, err = wm.SelectBigfileElements(w.ID, types.Bigfiles(1), false)
	if !errors.Is(err, wallet.ErrInsufficientFunds) {
		t.Fatal("expected insufficient funds error")
	}
	// release the selected outputs
	wm.Release(selected)

	// fund and broadcast a transaction
	utxos, basis, change, err := wm.SelectBigfileElements(w.ID, types.Bigfiles(101), false) // uses two outputs
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 2 {
		t.Fatalf("expected 2 outputs, got %v", len(utxos))
	} else if !change.Equals(types.Bigfiles(99)) {
		t.Fatalf("expected 99 BIG change, got %v", change)
	} else if basis != cm.Tip() {
		t.Fatalf("expected tip, got %v", basis)
	}
	txn := types.Transaction{
		BigfileOutputs: []types.BigfileOutput{
			{Address: types.VoidAddress, Value: types.Bigfiles(101)},
			{Address: addr, Value: change},
		},
	}
	for _, utxo := range utxos {
		txn.BigfileInputs = append(txn.BigfileInputs, types.BigfileInput{
			ParentID:         types.BigfileOutputID(utxo.ID),
			UnlockConditions: uc,
		})
		txn.Signatures = append(txn.Signatures, types.TransactionSignature{
			ParentID:      types.Hash256(utxo.ID),
			CoveredFields: types.CoveredFields{WholeTransaction: true},
		})
	}
	for i := range txn.Signatures {
		sigHash := cm.TipState().WholeSigHash(txn, txn.Signatures[i].ParentID, 0, 0, nil)
		sig := sk.SignHash(sigHash)
		txn.Signatures[i].Signature = sig[:]
	}

	known, err := cm.AddPoolTransactions([]types.Transaction{txn})
	if err != nil {
		t.Fatal(err)
	} else if known {
		t.Fatal("transaction was already known")
	}

	mineAndSync(t, types.VoidAddress, 1)

	events, err := wm.WalletEvents(w.ID, 0, 1)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeV1Transaction {
		t.Fatalf("expected transaction event, got %v", events[0].Type)
	} else if events[0].ID != types.Hash256(txn.ID()) {
		t.Fatalf("expected %v, got %v", txn.ID(), events[0].ID)
	} else if !events[0].BigfileOutflow().Sub(events[0].BigfileInflow()).Equals(types.Bigfiles(101)) {
		t.Fatalf("expected transaction value 101 BIG, got %v", events[0].BigfileOutflow().Sub(events[0].BigfileInflow()))
	}
}

func TestSelectBigfunds(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	sk := types.GeneratePrivateKey()
	uc := types.UnlockConditions{
		PublicKeys:         []types.UnlockKey{sk.PublicKey().UnlockKey()},
		SignaturesRequired: 1,
	}
	addr := uc.UnlockHash()

	network, genesisBlock := testutil.Network()
	genesisBlock.Transactions[0].BigfundOutputs[0].Address = addr
	network.InitialCoinbase = types.Bigfiles(100)
	network.MinimumCoinbase = types.Bigfiles(100)

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}
	cm := chain.NewManager(store, genesisState)

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	w, err := wm.AddWallet(wallet.Wallet{Name: "test"})
	if err != nil {
		t.Fatal(err)
	}

	err = wm.AddAddresses(w.ID, wallet.Address{
		Address: addr,
		SpendPolicy: &types.SpendPolicy{
			Type: types.PolicyTypeUnlockConditions(uc),
		},
	})
	if err != nil {
		t.Fatal(err)
	} else if err := wm.Scan(context.Background(), types.ChainIndex{}); err != nil {
		t.Fatal(err)
	}

	mineAndSync := func(t *testing.T, addr types.Address, n int) {
		t.Helper()

		for i := 0; i < n; i++ {
			testutil.MineBlocks(t, cm, addr, 1)
			waitForBlock(t, cm, db)
		}
	}
	mineAndSync(t, types.VoidAddress, 1)

	// check that the wallet has a bigfund utxo
	utxos, _, err := wm.UnspentBigfundOutputs(w.ID, 0, 1000)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 1 {
		t.Fatalf("expected 1 outputs, got %v", len(utxos))
	}

	balance, err := wm.WalletBalance(w.ID)
	if err != nil {
		t.Fatal(err)
	}

	// fund a transaction with more than the wallet balance
	_, _, _, err = wm.SelectBigfundElements(w.ID, balance.Bigfunds+1)
	if !errors.Is(err, wallet.ErrInsufficientFunds) {
		t.Fatal("expected insufficient funds error")
	}

	// fund and broadcast a transaction
	utxos, basis, change, err := wm.SelectBigfundElements(w.ID, balance.Bigfunds/2) // uses two outputs
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 1 {
		t.Fatalf("expected 1 utxo, got %v", len(utxos))
	} else if change != balance.Bigfunds/2 {
		t.Fatalf("expected %v SF change, got %v", balance.Bigfunds/2, change)
	} else if basis != cm.Tip() {
		t.Fatalf("expected tip, got %v", basis)
	}
	txn := types.Transaction{
		BigfundOutputs: []types.BigfundOutput{
			{Address: types.VoidAddress, Value: balance.Bigfunds / 2},
			{Address: addr, Value: change},
		},
	}
	for _, utxo := range utxos {
		txn.BigfundInputs = append(txn.BigfundInputs, types.BigfundInput{
			ParentID:         types.BigfundOutputID(utxo.ID),
			UnlockConditions: uc,
		})
		txn.Signatures = append(txn.Signatures, types.TransactionSignature{
			ParentID:      types.Hash256(utxo.ID),
			CoveredFields: types.CoveredFields{WholeTransaction: true},
		})
	}
	for i := range txn.Signatures {
		sigHash := cm.TipState().WholeSigHash(txn, txn.Signatures[i].ParentID, 0, 0, nil)
		sig := sk.SignHash(sigHash)
		txn.Signatures[i].Signature = sig[:]
	}

	known, err := cm.AddPoolTransactions([]types.Transaction{txn})
	if err != nil {
		t.Fatal(err)
	} else if known {
		t.Fatal("transaction was already known")
	}

	mineAndSync(t, types.VoidAddress, 1)

	events, err := wm.WalletEvents(w.ID, 0, 1)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeV1Transaction {
		t.Fatalf("expected transaction event, got %v", events[0].Type)
	} else if events[0].ID != types.Hash256(txn.ID()) {
		t.Fatalf("expected %v, got %v", txn.ID(), events[0].ID)
	} else if events[0].BigfundOutflow()-events[0].BigfundInflow() != balance.Bigfunds/2 {
		t.Fatalf("expected transaction value %v SF, got %v", balance.Bigfunds/2, events[0].BigfundOutflow()-events[0].BigfundInflow())
	}
}

func TestReorg(t *testing.T) {
	pk := types.GeneratePrivateKey()
	addr := types.StandardUnlockHash(pk.PublicKey())

	setupNode := func(t *testing.T, mode wallet.IndexMode) (consensus.State, *sqlite.Store, *chain.Manager, *wallet.Manager) {
		t.Helper()

		log := zaptest.NewLogger(t)
		dir := t.TempDir()
		db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })

		bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { bdb.Close() })

		network, genesisBlock := testV1Network(types.VoidAddress) // don't care about bigfunds

		store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
		if err != nil {
			t.Fatal(err)
		}
		cm := chain.NewManager(store, genesisState)

		wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")), wallet.WithIndexMode(mode))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { wm.Close() })
		return genesisState, db, cm, wm
	}

	testReorg := func(t *testing.T, genesisState consensus.State, db *sqlite.Store, cm *chain.Manager, wm *wallet.Manager) {
		w, err := wm.AddWallet(wallet.Wallet{Name: "test"})
		if err != nil {
			t.Fatal(err)
		} else if err := wm.AddAddresses(w.ID, wallet.Address{Address: addr}); err != nil {
			t.Fatal(err)
		}

		expectedPayout := cm.TipState().BlockReward()
		// mine a block sending the payout to the wallet
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, addr)}); err != nil {
			t.Fatal(err)
		}
		waitForBlock(t, cm, db)

		assertBalance := func(bigfile, immature types.Currency) error {
			b, err := wm.WalletBalance(w.ID)
			if err != nil {
				return fmt.Errorf("failed to check balance: %w", err)
			} else if !b.Bigfiles.Equals(bigfile) {
				return fmt.Errorf("expected bigfile balance %v, got %v", bigfile, b.Bigfiles)
			} else if !b.ImmatureBigfiles.Equals(immature) {
				return fmt.Errorf("expected immature bigfile balance %v, got %v", immature, b.ImmatureBigfiles)
			}
			return nil
		}

		if err := assertBalance(types.ZeroCurrency, expectedPayout); err != nil {
			t.Fatal(err)
		}

		// check that a payout event was recorded
		events, err := wm.WalletEvents(w.ID, 0, 100)
		if err != nil {
			t.Fatal(err)
		} else if len(events) != 1 {
			t.Fatalf("expected 1 event, got %v", len(events))
		} else if events[0].Type != wallet.EventTypeMinerPayout {
			t.Fatalf("expected payout event, got %v", events[0].Type)
		}

		// check that the utxo has not matured
		utxos, _, err := wm.UnspentBigfileOutputs(w.ID, 0, 100)
		if err != nil {
			t.Fatal(err)
		} else if len(utxos) != 0 {
			t.Fatalf("expected no outputs, got %v", len(utxos))
		}

		// mine to trigger a reorg
		var blocks []types.Block
		state := genesisState
		for i := 0; i < 10; i++ {
			block := mineBlock(state, nil, types.VoidAddress)
			blocks = append(blocks, block)
			state.Index.ID = block.ID()
			state.Index.Height++
		}
		if err := cm.AddBlocks(blocks); err != nil {
			t.Fatal(err)
		}
		waitForBlock(t, cm, db)

		// check that the balance was reverted
		if err := assertBalance(types.ZeroCurrency, types.ZeroCurrency); err != nil {
			t.Fatal(err)
		}

		// check that the payout event was reverted
		events, err = wm.WalletEvents(w.ID, 0, 100)
		if err != nil {
			t.Fatal(err)
		} else if len(events) != 0 {
			t.Fatalf("expected 0 events, got %v", len(events))
		}

		// check that the utxo was removed
		utxos, _, err = wm.UnspentBigfileOutputs(w.ID, 0, 100)
		if err != nil {
			t.Fatal(err)
		} else if len(utxos) != 0 {
			t.Fatalf("expected 0 outputs, got %v", len(utxos))
		}

		// mine a new payout
		expectedPayout = cm.TipState().BlockReward()
		maturityHeight := cm.TipState().MaturityHeight()
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, addr)}); err != nil {
			t.Fatal(err)
		}
		waitForBlock(t, cm, db)

		// check that the payout was received
		if err := assertBalance(types.ZeroCurrency, expectedPayout); err != nil {
			t.Fatal(err)
		}

		// check that a payout event was recorded
		events, err = wm.WalletEvents(w.ID, 0, 100)
		if err != nil {
			t.Fatal(err)
		} else if len(events) != 1 {
			t.Fatalf("expected 1 event, got %v", len(events))
		} else if events[0].Type != wallet.EventTypeMinerPayout {
			t.Fatalf("expected payout event, got %v", events[0].Type)
		}

		// check that the utxo has not matured
		utxos, _, err = wm.UnspentBigfileOutputs(w.ID, 0, 100)
		if err != nil {
			t.Fatal(err)
		} else if len(utxos) != 0 {
			t.Fatalf("expected no outputs, got %v", len(utxos))
		}

		// mine until the payout matures
		var prevState consensus.State
		for i := cm.TipState().Index.Height; i < maturityHeight+1; i++ {
			if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
				t.Fatal(err)
			}
			if i == maturityHeight-5 {
				prevState = cm.TipState()
			}
		}
		waitForBlock(t, cm, db)

		// check that the balance was updated
		if err := assertBalance(expectedPayout, types.ZeroCurrency); err != nil {
			t.Fatal(err)
		}

		// reorg the last few blocks to re-mature the payout
		blocks = nil
		state = prevState
		for i := 0; i < 10; i++ {
			blocks = append(blocks, mineBlock(state, nil, types.VoidAddress))
			state.Index.ID = blocks[len(blocks)-1].ID()
			state.Index.Height++
		}
		if err := cm.AddBlocks(blocks); err != nil {
			t.Fatal(err)
		}
		waitForBlock(t, cm, db)

		// check that the balance is correct
		if err := assertBalance(expectedPayout, types.ZeroCurrency); err != nil {
			t.Fatal(err)
		}

		// check that only the single utxo still exists
		utxos, _, err = wm.UnspentBigfileOutputs(w.ID, 0, 100)
		if err != nil {
			t.Fatal(err)
		} else if len(utxos) != 1 {
			t.Fatalf("expected 1 output, got %v", len(utxos))
		} else if utxos[0].BigfileOutput.Value.Cmp(expectedPayout) != 0 {
			t.Fatalf("expected %v, got %v", expectedPayout, utxos[0].BigfileOutput.Value)
		} else if utxos[0].MaturityHeight != maturityHeight {
			t.Fatalf("expected %v, got %v", maturityHeight, utxos[0].MaturityHeight)
		}
	}

	t.Run("IndexModePersonal", func(t *testing.T) {
		state, db, cm, w := setupNode(t, wallet.IndexModePersonal)
		testReorg(t, state, db, cm, w)
	})

	t.Run("IndexModeFull", func(t *testing.T) {
		state, db, cm, w := setupNode(t, wallet.IndexModeFull)
		testReorg(t, state, db, cm, w)
	})
}

func TestEphemeralBalance(t *testing.T) {
	pk := types.GeneratePrivateKey()
	addr := types.StandardUnlockHash(pk.PublicKey())

	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	network, genesisBlock := testV1Network(types.VoidAddress) // don't care about bigfunds

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)
	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	w, err := wm.AddWallet(wallet.Wallet{Name: "test"})
	if err != nil {
		t.Fatal(err)
	} else if err := wm.AddAddresses(w.ID, wallet.Address{Address: addr}); err != nil {
		t.Fatal(err)
	}

	expectedPayout := cm.TipState().BlockReward()
	maturityHeight := cm.TipState().MaturityHeight() + 1
	block := mineBlock(cm.TipState(), nil, addr)
	minerPayoutID := block.ID().MinerOutputID(0)
	// mine a block sending the payout to the wallet
	if err := cm.AddBlocks([]types.Block{block}); err != nil {
		t.Fatal(err)
	}
	waitForBlock(t, cm, db)

	// check that the payout was received
	balance, err := wm.AddressBalance(addr)
	if err != nil {
		t.Fatal(err)
	} else if !balance.ImmatureBigfiles.Equals(expectedPayout) {
		t.Fatalf("expected %v, got %v", expectedPayout, balance.ImmatureBigfiles)
	}

	// check that a payout event was recorded
	events, err := wm.WalletEvents(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeMinerPayout {
		t.Fatalf("expected payout event, got %v", events[0].Type)
	} else if events[0].ID != types.Hash256(minerPayoutID) {
		t.Fatalf("expected %v, got %v", minerPayoutID, events[0].ID)
	}

	// mine until the payout matures
	for i := cm.TipState().Index.Height; i < maturityHeight; i++ {
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
	}
	waitForBlock(t, cm, db)

	// create a transaction that spends the matured payout
	utxos, _, err := wm.UnspentBigfileOutputs(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 1 {
		t.Fatalf("expected 1 output, got %v", len(utxos))
	}

	unlockConditions := types.StandardUnlockConditions(pk.PublicKey())
	parentTxn := types.Transaction{
		BigfileInputs: []types.BigfileInput{
			{
				ParentID:         types.BigfileOutputID(utxos[0].ID),
				UnlockConditions: unlockConditions,
			},
		},
		BigfileOutputs: []types.BigfileOutput{
			{Address: addr, Value: types.Bigfiles(100)},
			{Address: types.VoidAddress, Value: utxos[0].BigfileOutput.Value.Sub(types.Bigfiles(100))},
		},
		Signatures: []types.TransactionSignature{
			{
				ParentID:       types.Hash256(utxos[0].ID),
				PublicKeyIndex: 0,
				CoveredFields:  types.CoveredFields{WholeTransaction: true},
			},
		},
	}
	parentSigHash := cm.TipState().WholeSigHash(parentTxn, types.Hash256(utxos[0].ID), 0, 0, nil)
	parentSig := pk.SignHash(parentSigHash)
	parentTxn.Signatures[0].Signature = parentSig[:]

	outputID := parentTxn.BigfileOutputID(0)
	txn := types.Transaction{
		BigfileInputs: []types.BigfileInput{
			{
				ParentID:         outputID,
				UnlockConditions: unlockConditions,
			},
		},
		BigfileOutputs: []types.BigfileOutput{
			{Address: types.VoidAddress, Value: types.Bigfiles(100)},
		},
		Signatures: []types.TransactionSignature{
			{
				ParentID:       types.Hash256(outputID),
				PublicKeyIndex: 0,
				CoveredFields:  types.CoveredFields{WholeTransaction: true},
			},
		},
	}
	sigHash := cm.TipState().WholeSigHash(txn, types.Hash256(outputID), 0, 0, nil)
	sig := pk.SignHash(sigHash)
	txn.Signatures[0].Signature = sig[:]

	txnset := []types.Transaction{parentTxn, txn}

	// broadcast the transactions
	revertState := cm.TipState()
	if err := cm.AddBlocks([]types.Block{mineBlock(revertState, txnset, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	waitForBlock(t, cm, db)

	// check that the payout was spent
	balance, err = wm.AddressBalance(addr)
	if err != nil {
		t.Fatal(err)
	} else if !balance.Bigfiles.IsZero() {
		t.Fatalf("expected 0, got %v", balance.Bigfiles)
	}

	// check that both transactions were added
	events, err = wm.WalletEvents(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 3 { // 1 payout, 2 transactions
		t.Fatalf("expected 3 events, got %v", len(events))
	} else if events[2].Type != wallet.EventTypeMinerPayout {
		t.Fatalf("expected miner payout event, got %v", events[2].Type)
	} else if events[1].Type != wallet.EventTypeV1Transaction {
		t.Fatalf("expected transaction event, got %v", events[1].Type)
	} else if events[0].Type != wallet.EventTypeV1Transaction {
		t.Fatalf("expected transaction event, got %v", events[0].Type)
	} else if events[1].ID != types.Hash256(parentTxn.ID()) { // parent txn first
		t.Fatalf("expected %v, got %v", parentTxn.ID(), events[1].ID)
	} else if events[0].ID != types.Hash256(txn.ID()) { // child txn second
		t.Fatalf("expected %v, got %v", txn.ID(), events[0].ID)
	}

	// trigger a reorg
	var blocks []types.Block
	state := revertState
	for i := 0; i < 2; i++ {
		blocks = append(blocks, mineBlock(state, nil, types.VoidAddress))
		state.Index.ID = blocks[len(blocks)-1].ID()
		state.Index.Height++
	}
	if err := cm.AddBlocks(blocks); err != nil {
		t.Fatal(err)
	}
	waitForBlock(t, cm, db)

	// check that the transaction was reverted
	balance, err = wm.AddressBalance(addr)
	if err != nil {
		t.Fatal(err)
	} else if !balance.Bigfiles.Equals(expectedPayout) {
		t.Fatalf("expected %v, got %v", expectedPayout, balance.Bigfiles)
	}

	// check that only the payout event remains
	events, err = wm.WalletEvents(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 events, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeMinerPayout {
		t.Fatalf("expected payout event, got %v", events[0].Type)
	}
}

func TestWalletAddresses(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	network, genesisBlock := testV1Network(types.VoidAddress) // don't care about bigfunds

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)
	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	// Add a wallet
	w := wallet.Wallet{
		Name:        "test",
		Description: "hello, world!",
		Metadata:    json.RawMessage(`{"foo": "bar"}`),
	}
	w, err = wm.AddWallet(w)
	if err != nil {
		t.Fatal(err)
	}

	wallets, err := wm.Wallets()
	if err != nil {
		t.Fatal(err)
	} else if len(wallets) != 1 {
		t.Fatal("expected 1 wallet, got", len(wallets))
	} else if wallets[0].ID != w.ID {
		t.Fatal("unexpected wallet ID", wallets[0].ID)
	} else if wallets[0].Name != "test" {
		t.Fatal("unexpected wallet name", wallets[0].Name)
	} else if wallets[0].Description != "hello, world!" {
		t.Fatal("unexpected description", wallets[0].Description)
	} else if !bytes.Equal(wallets[0].Metadata, []byte(`{"foo": "bar"}`)) {
		t.Fatal("unexpected metadata", wallets[0].Metadata)
	} else if wallets[0].DateCreated.IsZero() || !wallets[0].DateCreated.Equal(w.DateCreated) {
		t.Fatalf("expected creation date %s, got %s", w.DateCreated, wallets[0].DateCreated)
	} else if wallets[0].LastUpdated.IsZero() || !wallets[0].LastUpdated.Equal(w.LastUpdated) {
		t.Fatalf("expected last updated date %s, got %s", w.LastUpdated, wallets[0].LastUpdated)
	}

	// Add an address
	pk := types.GeneratePrivateKey()
	spendPolicy := types.PolicyPublicKey(pk.PublicKey())
	address := spendPolicy.Address()

	addr := wallet.Address{
		Address:     address,
		SpendPolicy: &spendPolicy,
		Description: "hello, world",
	}
	err = wm.AddAddresses(w.ID, addr)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the address was added
	addresses, err := wm.Addresses(w.ID)
	if err != nil {
		t.Fatal(err)
	} else if len(addresses) != 1 {
		t.Fatal("expected 1 address, got", len(addresses))
	} else if addresses[0].Address != address {
		t.Fatal("unexpected address", addresses[0].Address)
	} else if addresses[0].Description != "hello, world" {
		t.Fatal("unexpected description", addresses[0].Description)
	} else if *addresses[0].SpendPolicy != spendPolicy {
		t.Fatal("unexpected spend policy", addresses[0].SpendPolicy)
	}

	// update the addresses metadata and description
	addr.Description = "goodbye, world"
	addr.Metadata = json.RawMessage(`{"foo": "bar"}`)

	if err := wm.AddAddresses(w.ID, addr); err != nil {
		t.Fatal(err)
	}

	// Check that the address was added
	addresses, err = wm.Addresses(w.ID)
	if err != nil {
		t.Fatal(err)
	} else if len(addresses) != 1 {
		t.Fatal("expected 1 address, got", len(addresses))
	} else if addresses[0].Address != address {
		t.Fatal("unexpected address", addresses[0].Address)
	} else if addresses[0].Description != "goodbye, world" {
		t.Fatal("unexpected description", addresses[0].Description)
	} else if *addresses[0].SpendPolicy != spendPolicy {
		t.Fatal("unexpected spend policy", addresses[0].SpendPolicy)
	} else if string(addresses[0].Metadata) != `{"foo": "bar"}` {
		t.Fatal("unexpected metadata", addresses[0].Metadata)
	}

	// Remove the address
	err = wm.RemoveAddress(w.ID, address)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the address was removed
	addresses, err = wm.Addresses(w.ID)
	if err != nil {
		t.Fatal(err)
	} else if len(addresses) != 0 {
		t.Fatal("expected 0 addresses, got", len(addresses))
	}
}

func TestScan(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	// mine a single payout to the wallet
	pk := types.GeneratePrivateKey()
	addr := types.StandardUnlockHash(pk.PublicKey())

	network, genesisBlock := testutil.Network()
	// send the bigfunds to the owned address
	genesisBlock.Transactions[0].BigfundOutputs[0].Address = addr

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	// create a wallet with no addresses
	w, err := wm.AddWallet(wallet.Wallet{Name: "test"})
	if err != nil {
		t.Fatal(err)
	}

	// add the address to the wallet
	if err := wm.AddAddresses(w.ID, wallet.Address{Address: addr}); err != nil {
		t.Fatal(err)
	}
	// rescan to get the genesis Bigfund state
	if err := wm.Scan(context.Background(), types.ChainIndex{}); err != nil {
		t.Fatal(err)
	}

	checkBalance := func(bigfile, immature types.Currency) error {
		waitForBlock(t, cm, db)

		// note: the bigfund balance is currently hardcoded to the number of
		// bigfunds in genesis. If we ever modify this test to also spend
		// bigfunds, this will need to be updated.
		b, err := wm.WalletBalance(w.ID)
		if err != nil {
			return fmt.Errorf("failed to check balance: %w", err)
		} else if !b.Bigfiles.Equals(bigfile) {
			return fmt.Errorf("expected bigfile balance %v, got %v", bigfile, b.Bigfiles)
		} else if !b.ImmatureBigfiles.Equals(immature) {
			return fmt.Errorf("expected immature bigfile balance %v, got %v", immature, b.ImmatureBigfiles)
		} else if b.Bigfunds != network.GenesisState().BigfundCount() {
			return fmt.Errorf("expected bigfund balance %v, got %v", network.GenesisState().BigfundCount(), b.Bigfunds)
		}
		return nil
	}

	// check that the wallet has no balance
	if err := checkBalance(types.ZeroCurrency, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	expectedBalance1 := cm.TipState().BlockReward()

	// mine a block to fund the first address
	b, ok := coreutils.MineBlock(cm, addr, 5*time.Second)
	if !ok {
		t.Fatal("failed to mine block")
	} else if err := cm.AddBlocks([]types.Block{b}); err != nil {
		t.Fatal(err)
	}

	expectedBalance2 := cm.TipState().BlockReward()

	// mine a block to fund the second address
	b, ok = coreutils.MineBlock(cm, addr2, 5*time.Second)
	if !ok {
		t.Fatal("failed to mine block")
	} else if err := cm.AddBlocks([]types.Block{b}); err != nil {
		t.Fatal(err)
	}

	// check that the wallet has one immature payout
	if err := checkBalance(types.ZeroCurrency, expectedBalance1); err != nil {
		t.Fatal(err)
	}

	// mine until the first payout matures
	for i := cm.Tip().Height; i < genesisState.MaturityHeight(); i++ {
		if b, ok := coreutils.MineBlock(cm, types.VoidAddress, 5*time.Second); !ok {
			t.Fatal("failed to mine block")
		} else if err := cm.AddBlocks([]types.Block{b}); err != nil {
			t.Fatal(err)
		}
	}

	// check that the wallet balance has matured
	if err := checkBalance(expectedBalance1, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// scan for changes
	if err := wm.Scan(context.Background(), types.ChainIndex{}); err != nil {
		t.Fatal(err)
	}

	// check that the wallet balance did not change
	if err := checkBalance(expectedBalance1, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// add the second address to the wallet
	if err := wm.AddAddresses(w.ID, wallet.Address{Address: addr2}); err != nil {
		t.Fatal(err)
	} else if err := checkBalance(expectedBalance1, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// scan for changes
	if err := wm.Scan(context.Background(), types.ChainIndex{}); err != nil {
		t.Fatal(err)
	}

	if err := checkBalance(expectedBalance1, expectedBalance2); err != nil {
		t.Fatal(err)
	}

	// mine a block to mature the second payout
	b, ok = coreutils.MineBlock(cm, types.VoidAddress, 5*time.Second)
	if !ok {
		t.Fatal("failed to mine block")
	} else if err := cm.AddBlocks([]types.Block{b}); err != nil {
		t.Fatal(err)
	}

	// check that the wallet balance has matured
	if err := checkBalance(expectedBalance1.Add(expectedBalance2), types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// sanity check
	if err := wm.Scan(context.Background(), types.ChainIndex{}); err != nil {
		t.Fatal(err)
	}

	// check that the wallet balance has matured
	if err := checkBalance(expectedBalance1.Add(expectedBalance2), types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}
}

func TestBigfunds(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	// mine a single payout to the wallet
	pk := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk.PublicKey())

	network, genesisBlock := testutil.Network()
	// send the bigfunds to the owned address
	genesisBlock.Transactions[0].BigfundOutputs[0].Address = addr1

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	// create a wallet with no addresses
	w1, err := wm.AddWallet(wallet.Wallet{Name: "test1"})
	if err != nil {
		t.Fatal(err)
	}

	// add the address to the wallet
	if err := wm.AddAddresses(w1.ID, wallet.Address{Address: addr1}); err != nil {
		t.Fatal(err)
	}

	checkBalance := func(walletID wallet.ID, bigfunds uint64) error {
		waitForBlock(t, cm, db)

		b, err := wm.WalletBalance(walletID)
		if err != nil {
			return fmt.Errorf("failed to check balance: %w", err)
		} else if b.Bigfunds != bigfunds {
			return fmt.Errorf("expected bigfund balance %v, got %v", bigfunds, b.Bigfunds)
		}
		return nil
	}

	if err := wm.Scan(context.Background(), types.ChainIndex{}); err != nil {
		t.Fatal(err)
	} else if err := checkBalance(w1.ID, network.GenesisState().BigfundCount()); err != nil {
		t.Fatal(err)
	}

	// split the bigfunds between the two addresses
	sendAmount := network.GenesisState().BigfundCount() / 2
	parentID := genesisBlock.Transactions[0].BigfundOutputID(0)
	txn := types.Transaction{
		BigfundInputs: []types.BigfundInput{
			{
				ParentID:         parentID,
				UnlockConditions: types.StandardUnlockConditions(pk.PublicKey()),
			},
		},
		BigfundOutputs: []types.BigfundOutput{
			{Address: addr2, Value: sendAmount},
			{Address: addr1, Value: sendAmount},
		},
		Signatures: []types.TransactionSignature{
			{
				ParentID:      types.Hash256(parentID),
				CoveredFields: types.CoveredFields{WholeTransaction: true},
			},
		},
	}
	state := cm.TipState()
	sigHash := state.WholeSigHash(txn, txn.Signatures[0].ParentID, 0, 0, nil)
	sig := pk.SignHash(sigHash)
	txn.Signatures[0].Signature = sig[:]

	if _, err := cm.AddPoolTransactions([]types.Transaction{txn}); err != nil {
		t.Fatal(err)
	}

	// check that the transaction made it into the pool
	if events, err := wm.WalletUnconfirmedEvents(w1.ID); err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeV1Transaction {
		t.Fatalf("expected transaction event, got %v", events[0].Type)
	} else if events[0].ID != types.Hash256(txn.ID()) {
		t.Fatalf("expected %v, got %v", txn.ID(), events[0].ID)
	} else if events[0].Relevant[0] != addr1 {
		t.Fatalf("expected %v, got %v", addr1, events[0].Relevant[0])
	}

	if b, ok := coreutils.MineBlock(cm, types.VoidAddress, 5*time.Second); !ok {
		t.Fatal("failed to mine block")
	} else if err := cm.AddBlocks([]types.Block{b}); err != nil {
		t.Fatal(err)
	} else if err := checkBalance(w1.ID, sendAmount); err != nil {
		t.Fatal(err)
	}

	// rescan for sanity check
	if err := wm.Scan(context.Background(), types.ChainIndex{}); err != nil {
		t.Fatal(err)
	} else if err := checkBalance(w1.ID, sendAmount); err != nil {
		t.Fatal(err)
	}

	// add a second wallet
	w2, err := wm.AddWallet(wallet.Wallet{Name: "test2"})
	if err != nil {
		t.Fatal(err)
	} else if err := wm.AddAddresses(w2.ID, wallet.Address{Address: addr2}); err != nil {
		t.Fatal(err)
	}

	// wallet should have no balance since it hasn't been scanned
	if err := checkBalance(w2.ID, 0); err != nil {
		t.Fatal(err)
	}

	// rescan for the second wallet
	if err := wm.Scan(context.Background(), types.ChainIndex{}); err != nil {
		t.Fatal(err)
	} else if err := checkBalance(w2.ID, sendAmount); err != nil {
		t.Fatal(err)
	} else if err := checkBalance(w1.ID, sendAmount); err != nil {
		t.Fatal(err)
	}

	// add the first address to the second wallet
	if err := wm.AddAddresses(w2.ID, wallet.Address{Address: addr1}); err != nil {
		t.Fatal(err)
	}
	// rescan shouldn't be necessary since the address was already scanned
	if err := checkBalance(w2.ID, network.GenesisState().BigfundCount()); err != nil {
		t.Fatal(err)
	}
}

func TestOrphans(t *testing.T) {
	pk := types.GeneratePrivateKey()
	addr := types.StandardUnlockHash(pk.PublicKey())

	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	network, genesisBlock := testV1Network(types.VoidAddress) // don't care about bigfunds
	network.HardforkV2.AllowHeight = 200
	network.HardforkV2.RequireHeight = 201

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}
	cm := chain.NewManager(store, genesisState)

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	w, err := wm.AddWallet(wallet.Wallet{Name: "test"})
	if err != nil {
		t.Fatal(err)
	} else if err := wm.AddAddresses(w.ID, wallet.Address{Address: addr}); err != nil {
		t.Fatal(err)
	}

	expectedPayout := cm.TipState().BlockReward()
	maturityHeight := cm.TipState().MaturityHeight()
	// mine a block sending the payout to the wallet
	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, addr)}); err != nil {
		t.Fatal(err)
	}

	// mine until the maturity height
	for i := cm.TipState().Index.Height; i < maturityHeight+1; i++ {
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
	}
	waitForBlock(t, cm, db)

	assertBalance := func(bigfile, immature types.Currency) error {
		b, err := wm.WalletBalance(w.ID)
		if err != nil {
			return fmt.Errorf("failed to check balance: %w", err)
		} else if !b.ImmatureBigfiles.Equals(immature) {
			return fmt.Errorf("expected immature bigfile balance %v, got %v", immature, b.ImmatureBigfiles)
		} else if !b.Bigfiles.Equals(bigfile) {
			return fmt.Errorf("expected bigfile balance %v, got %v", bigfile, b.Bigfiles)
		}
		return nil
	}

	if err := assertBalance(expectedPayout, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// check that a payout event was recorded
	events, err := wm.WalletEvents(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeMinerPayout {
		t.Fatalf("expected payout event, got %v", events[0].Type)
	}

	// check that the utxo was created
	utxos, _, err := wm.UnspentBigfileOutputs(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 1 {
		t.Fatalf("expected 1 output, got %v", len(utxos))
	} else if utxos[0].BigfileOutput.Value.Cmp(expectedPayout) != 0 {
		t.Fatalf("expected %v, got %v", expectedPayout, utxos[0].BigfileOutput.Value)
	} else if utxos[0].MaturityHeight != maturityHeight {
		t.Fatalf("expected %v, got %v", maturityHeight, utxos[0].MaturityHeight)
	}

	resetState := cm.TipState()

	// send a transaction that will be orphaned
	txn := types.Transaction{
		BigfileInputs: []types.BigfileInput{
			{
				ParentID:         types.BigfileOutputID(utxos[0].ID),
				UnlockConditions: types.StandardUnlockConditions(pk.PublicKey()),
			},
		},
		BigfileOutputs: []types.BigfileOutput{
			{Address: types.VoidAddress, Value: expectedPayout.Div64(2)}, // send the other half to the void
			{Address: addr, Value: expectedPayout.Div64(2)},              // send half the payout back to the wallet
		},
		Signatures: []types.TransactionSignature{
			{
				ParentID:       types.Hash256(utxos[0].ID),
				PublicKeyIndex: 0,
				CoveredFields:  types.CoveredFields{WholeTransaction: true},
			},
		},
	}
	sigHash := cm.TipState().WholeSigHash(txn, types.Hash256(utxos[0].ID), 0, 0, nil)
	sig := pk.SignHash(sigHash)
	txn.Signatures[0].Signature = sig[:]

	// broadcast the transaction
	if _, err := cm.AddPoolTransactions([]types.Transaction{txn}); err != nil {
		t.Fatal(err)
	} else if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), []types.Transaction{txn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	waitForBlock(t, cm, db)

	if err := assertBalance(expectedPayout.Div64(2), types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// check that the transaction event was recorded
	events, err = wm.WalletEvents(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 2 {
		t.Fatalf("expected 2 events, got %v", len(events))
	}

	// simulate an interrupted rescan by closing the wallet manager, resetting the
	// last scan index, and initializing a new wallet manager.
	if err := wm.Close(); err != nil {
		t.Fatal(err)
	} else if err := db.ResetLastIndex(); err != nil {
		t.Fatal(err)
	}

	// mine to trigger a reorg. The underlying store must properly revert the
	// orphaned blocks that will not be cleanly reverted since the rescan was
	// interrupted.
	var blocks []types.Block
	state := resetState
	for i := 0; i < 5; i++ {
		blocks = append(blocks, mineBlock(state, nil, types.VoidAddress))
		state.Index.ID = blocks[len(blocks)-1].ID()
		state.Index.Height++
	}
	if err := cm.AddBlocks(blocks); err != nil {
		t.Fatal(err)
	}

	wm, err = wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	waitForBlock(t, cm, db)

	// check that the transaction was reverted
	if err := assertBalance(expectedPayout, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// check that the transaction event was reverted
	events, err = wm.WalletEvents(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", len(events))
	}

	// check that the utxo was reverted
	utxos, _, err = wm.UnspentBigfileOutputs(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 1 {
		t.Fatalf("expected 1 output, got %v", len(utxos))
	} else if !utxos[0].BigfileOutput.Value.Equals(expectedPayout) {
		t.Fatalf("expected %v, got %v", expectedPayout, utxos[0].BigfileOutput.Value)
	}
}

func TestFullIndex(t *testing.T) {
	pk := types.GeneratePrivateKey()
	addr := types.StandardUnlockHash(pk.PublicKey())

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	network, genesisBlock := testV2Network(addr2)
	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}
	cm := chain.NewManager(store, genesisState)

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")), wallet.WithIndexMode(wallet.IndexModeFull))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	waitForBlock(t, cm, db)

	assertBalance := func(t *testing.T, address types.Address, bigfile, immature types.Currency, bigfund uint64) {
		t.Helper()

		b, err := wm.AddressBalance(address)
		if err != nil {
			t.Fatal(err)
		} else if !b.ImmatureBigfiles.Equals(immature) {
			t.Fatalf("expected immature bigfile balance %v, got %v", immature, b.ImmatureBigfiles)
		} else if !b.Bigfiles.Equals(bigfile) {
			t.Fatalf("expected bigfile balance %v, got %v", bigfile, b.Bigfiles)
		} else if b.Bigfunds != bigfund {
			t.Fatalf("expected bigfund balance %v, got %v", bigfund, b.Bigfunds)
		}
	}

	// check the events are empty for the first address
	if events, err := wm.AddressEvents(addr, 0, 100); err != nil {
		t.Fatal(err)
	} else if len(events) != 0 {
		t.Fatalf("expected 0 events, got %v", len(events))
	}

	// assert that the airdropped bigfunds are on the second address
	assertBalance(t, addr2, types.ZeroCurrency, types.ZeroCurrency, cm.TipState().BigfundCount())
	// check the events for the air dropped bigfunds
	if events, err := wm.AddressEvents(addr2, 0, 100); err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeV1Transaction {
		t.Fatalf("expected transaction event, got %v", events[0].Type)
	}

	// mine a block and send the payout to the first address
	expectedBalance1 := cm.TipState().BlockReward()
	maturityHeight := cm.TipState().MaturityHeight()
	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, addr)}); err != nil {
		t.Fatal(err)
	}
	waitForBlock(t, cm, db)

	// check the payout was received
	if events, err := wm.AddressEvents(addr, 0, 100); err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 events, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeMinerPayout {
		t.Fatalf("expected miner payout event, got %v", events[0].Type)
	}

	assertBalance(t, addr, types.ZeroCurrency, expectedBalance1, 0)

	// mine until the payout matures
	for i := cm.TipState().Index.Height; i < maturityHeight; i++ {
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
	}
	waitForBlock(t, cm, db)

	// check that the events did not change
	if events, err := wm.AddressEvents(addr, 0, 100); err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 events, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeMinerPayout {
		t.Fatalf("expected miner payout event, got %v", events[0].Type)
	}

	assertBalance(t, addr, expectedBalance1, types.ZeroCurrency, 0)
	assertBalance(t, addr2, types.ZeroCurrency, types.ZeroCurrency, cm.TipState().BigfundCount())

	// send half bigfiles to the second address
	utxos, _, err := wm.AddressBigfileOutputs(addr, false, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, se := range utxos {
		if bige, err := wm.BigfileElement(types.BigfileOutputID(se.ID)); err != nil {
			t.Fatal(err)
		} else if !reflect.DeepEqual(bige, se.BigfileElement) {
			t.Fatalf("expected %v, got %v", se, bige)
		}
	}

	policy := types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk.PublicKey()))
	txn := types.V2Transaction{
		BigfileInputs: []types.V2BigfileInput{
			{
				Parent: utxos[0].BigfileElement,
				SatisfiedPolicy: types.SatisfiedPolicy{
					Policy: types.SpendPolicy{
						Type: policy,
					},
				},
			},
		},
		BigfileOutputs: []types.BigfileOutput{
			{Address: addr2, Value: utxos[0].BigfileOutput.Value.Div64(2)},
			{Address: addr, Value: utxos[0].BigfileOutput.Value.Div64(2)},
		},
	}
	txn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(cm.TipState().InputSigHash(txn))}

	if err := cm.AddBlocks([]types.Block{mineV2Block(cm.TipState(), []types.V2Transaction{txn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	waitForBlock(t, cm, db)

	assertBalance(t, addr, expectedBalance1.Div64(2), types.ZeroCurrency, 0)
	assertBalance(t, addr2, expectedBalance1.Div64(2), types.ZeroCurrency, cm.TipState().BigfundCount())

	// check the events for the transaction
	if events, err := wm.AddressEvents(addr, 0, 100); err != nil {
		t.Fatal(err)
	} else if len(events) != 2 {
		t.Fatalf("expected 2 events, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeV2Transaction {
		t.Fatalf("expected transaction event, got %v", events[0].Type)
	}

	// check the events for the second address
	if events, err := wm.AddressEvents(addr2, 0, 100); err != nil {
		t.Fatal(err)
	} else if len(events) != 2 {
		t.Fatalf("expected 2 event, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeV2Transaction {
		t.Fatalf("expected transaction event, got %v", events[0].Type)
	}

	sf, _, err := wm.AddressBigfundOutputs(addr2, false, 0, 100)
	if err != nil {
		t.Fatal(err)
	}

	for _, se := range sf {
		if bfe, err := wm.BigfundElement(types.BigfundOutputID(se.ID)); err != nil {
			t.Fatal(err)
		} else if !reflect.DeepEqual(bfe, se.BigfundElement) {
			t.Fatalf("expected %v, got %v", se, bfe)
		}
	}

	// send the bigfunds to the first address
	policy = types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk2.PublicKey()))
	txn = types.V2Transaction{
		BigfundInputs: []types.V2BigfundInput{
			{
				Parent: sf[0].BigfundElement,
				SatisfiedPolicy: types.SatisfiedPolicy{
					Policy: types.SpendPolicy{
						Type: policy,
					},
				},
				ClaimAddress: addr2, // claim address shouldn't create an event since the value is 0
			},
		},
		BigfundOutputs: []types.BigfundOutput{
			{Address: addr, Value: sf[0].BigfundOutput.Value},
		},
	}
	txn.BigfundInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk2.SignHash(cm.TipState().InputSigHash(txn))}

	if err := cm.AddBlocks([]types.Block{mineV2Block(cm.TipState(), []types.V2Transaction{txn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	waitForBlock(t, cm, db)

	assertBalance(t, addr, expectedBalance1.Div64(2), types.ZeroCurrency, cm.TipState().BigfundCount())
	assertBalance(t, addr2, expectedBalance1.Div64(2), types.ZeroCurrency, 0)

	// check the events for the transaction
	if events, err := wm.AddressEvents(addr2, 0, 100); err != nil {
		t.Fatal(err)
	} else if len(events) != 3 {
		t.Fatalf("expected 3 events, got %v", len(events))
	}

	// check the events for the first address
	if events, err := wm.AddressEvents(addr, 0, 100); err != nil {
		t.Fatal(err)
	} else if len(events) != 3 {
		t.Fatalf("expected 3 events, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeV2Transaction {
		t.Fatalf("expected transaction event, got %v", events[0].Type)
	}
}

func TestEvents(t *testing.T) {
	pk := types.GeneratePrivateKey()
	addr := types.StandardUnlockHash(pk.PublicKey())

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	network, genesisBlock := testV2Network(addr2)
	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}
	cm := chain.NewManager(store, genesisState)

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")), wallet.WithIndexMode(wallet.IndexModeFull))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	waitForBlock(t, cm, db)

	assertBalance := func(t *testing.T, address types.Address, bigfile, immature types.Currency, bigfund uint64) {
		t.Helper()

		b, err := wm.AddressBalance(address)
		if err != nil {
			t.Fatal(err)
		} else if !b.ImmatureBigfiles.Equals(immature) {
			t.Fatalf("expected immature bigfile balance %v, got %v", immature, b.ImmatureBigfiles)
		} else if !b.Bigfiles.Equals(bigfile) {
			t.Fatalf("expected bigfile balance %v, got %v", bigfile, b.Bigfiles)
		} else if b.Bigfunds != bigfund {
			t.Fatalf("expected bigfund balance %v, got %v", bigfund, b.Bigfunds)
		}
	}

	// check the events are empty for the first address
	if events, err := wm.AddressEvents(addr, 0, 100); err != nil {
		t.Fatal(err)
	} else if len(events) != 0 {
		t.Fatalf("expected 0 events, got %v", len(events))
	}

	// assert that the airdropped bigfunds are on the second address
	assertBalance(t, addr2, types.ZeroCurrency, types.ZeroCurrency, cm.TipState().BigfundCount())
	// check the events for the air dropped bigfunds
	if events, err := wm.AddressEvents(addr2, 0, 100); err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeV1Transaction {
		t.Fatalf("expected transaction event, got %v", events[0].Type)
	}

	// mine a block and send the payout to the first address
	expectedBalance1 := cm.TipState().BlockReward()
	maturityHeight := cm.TipState().MaturityHeight()
	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, addr)}); err != nil {
		t.Fatal(err)
	}
	waitForBlock(t, cm, db)

	// check the payout was received
	events, err := wm.AddressEvents(addr, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 events, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeMinerPayout {
		t.Fatalf("expected miner payout event, got %v", events[0].Type)
	}

	expected := events[0]
	expected.Relevant = nil // clear the relevant field for deep equal
	events2, err := wm.Events([]types.Hash256{events[0].ID})
	if err != nil {
		t.Fatalf("expected to get event: %v", err)
	} else if !reflect.DeepEqual(events2[0], expected) {
		t.Fatalf("expected event %v to match %v", expected, events2[0])
	}

	assertBalance(t, addr, types.ZeroCurrency, expectedBalance1, 0)

	// mine until the payout matures
	for i := cm.TipState().Index.Height; i < maturityHeight; i++ {
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
	}
	waitForBlock(t, cm, db)

	// check that the events did not change
	if events, err := wm.AddressEvents(addr, 0, 100); err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 events, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeMinerPayout {
		t.Fatalf("expected miner payout event, got %v", events[0].Type)
	}

	assertBalance(t, addr, expectedBalance1, types.ZeroCurrency, 0)
	assertBalance(t, addr2, types.ZeroCurrency, types.ZeroCurrency, cm.TipState().BigfundCount())

	// send half bigfiles to the second address
	utxos, basis, err := wm.AddressBigfileOutputs(addr, false, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if basis != cm.Tip() {
		t.Fatalf("expected basis to be the current tip")
	}

	policy := types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk.PublicKey()))
	txn := types.V2Transaction{
		BigfileInputs: []types.V2BigfileInput{
			{
				Parent: utxos[0].BigfileElement,
				SatisfiedPolicy: types.SatisfiedPolicy{
					Policy: types.SpendPolicy{
						Type: policy,
					},
				},
			},
		},
		BigfileOutputs: []types.BigfileOutput{
			{Address: addr2, Value: utxos[0].BigfileOutput.Value.Div64(2)},
			{Address: addr, Value: utxos[0].BigfileOutput.Value.Div64(2)},
		},
	}
	txn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(cm.TipState().InputSigHash(txn))}

	if _, err := cm.AddV2PoolTransactions(basis, []types.V2Transaction{txn}); err != nil {
		t.Fatal(err)
	}
	mineAndSync(t, cm, db, types.VoidAddress, 1)

	assertBalance(t, addr, expectedBalance1.Div64(2), types.ZeroCurrency, 0)
	assertBalance(t, addr2, expectedBalance1.Div64(2), types.ZeroCurrency, cm.TipState().BigfundCount())

	// check the events for the transaction
	events, err = wm.AddressEvents(addr, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 2 {
		t.Fatalf("expected 2 events, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeV2Transaction {
		t.Fatalf("expected transaction event, got %v", events[0].Type)
	}

	expected = events[0]
	expected.Relevant = nil // clear the relevant field for deep equal
	if events2, err := wm.Events([]types.Hash256{expected.ID}); err != nil {
		t.Fatalf("expected to get event: %v", err)
	} else if !reflect.DeepEqual(events2[0], expected) {
		t.Fatalf("expected event %v to match %v", expected, events2)
	}

	// check the events for the second address
	events, err = wm.AddressEvents(addr2, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 2 {
		t.Fatalf("expected 2 event, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeV2Transaction {
		t.Fatalf("expected transaction event, got %v", events[0].Type)
	}

	expected = events[0]
	expected.Relevant = nil // clear the relevant field for deep equal
	events2, err = wm.Events([]types.Hash256{events[0].ID})
	if err != nil {
		t.Fatalf("expected to get event: %v", err)
	} else if !reflect.DeepEqual(events2[0], expected) {
		t.Fatalf("expected event %v to match %v", expected, events2[0])
	}

	sf, _, err := wm.AddressBigfundOutputs(addr2, false, 0, 100)
	if err != nil {
		t.Fatal(err)
	}

	// send the bigfunds to the first address
	policy = types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk2.PublicKey()))
	txn = types.V2Transaction{
		BigfundInputs: []types.V2BigfundInput{
			{
				Parent: sf[0].BigfundElement,
				SatisfiedPolicy: types.SatisfiedPolicy{
					Policy: types.SpendPolicy{
						Type: policy,
					},
				},
				ClaimAddress: addr2, // claim address shouldn't create an event since the value is 0
			},
		},
		BigfundOutputs: []types.BigfundOutput{
			{Address: addr, Value: sf[0].BigfundOutput.Value},
		},
	}
	txn.BigfundInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk2.SignHash(cm.TipState().InputSigHash(txn))}

	if err := cm.AddBlocks([]types.Block{mineV2Block(cm.TipState(), []types.V2Transaction{txn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	waitForBlock(t, cm, db)

	assertBalance(t, addr, expectedBalance1.Div64(2), types.ZeroCurrency, cm.TipState().BigfundCount())
	assertBalance(t, addr2, expectedBalance1.Div64(2), types.ZeroCurrency, 0)

	// check the events for the transaction
	events, err = wm.AddressEvents(addr2, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 3 {
		t.Fatalf("expected 4 events, got %v", len(events))
	}

	expected = events[0]
	expected.Relevant = nil // clear the relevant field for deep equal
	if events2, err := wm.Events([]types.Hash256{expected.ID}); err != nil {
		t.Fatalf("expected to get event: %v", err)
	} else if !reflect.DeepEqual(events2[0], expected) {
		t.Fatalf("expected event %v to match %v", expected, events2)
	}

	// check the events for the first address
	events, err = wm.AddressEvents(addr, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 3 {
		t.Fatalf("expected 3 events, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeV2Transaction {
		t.Fatalf("expected transaction event, got %v", events[0].Type)
	}

	expected = events[0]
	expected.Relevant = nil // clear the relevant field for deep equal
	if events2, err := wm.Events([]types.Hash256{expected.ID}); err != nil {
		t.Fatalf("expected to get event: %v", err)
	} else if !reflect.DeepEqual(events2[0], expected) {
		t.Fatalf("expected event %v to match %v", expected, events2)
	}
}

func TestWalletUnconfirmedEvents(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	// mine a single payout to the wallet
	pk := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk.PublicKey())

	network, genesisBlock := testutil.Network()
	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	// create a wallet with no addresses
	w1, err := wm.AddWallet(wallet.Wallet{Name: "test1"})
	if err != nil {
		t.Fatal(err)
	}

	// add the address to the wallet
	if err := wm.AddAddresses(w1.ID, wallet.Address{Address: addr1}); err != nil {
		t.Fatal(err)
	}

	// mine a block sending the payout to the wallet
	mineAndSync(t, cm, db, addr1, 1)
	mineAndSync(t, cm, db, types.VoidAddress, int(network.MaturityDelay))

	utxos, _, err := wm.UnspentBigfileOutputs(w1.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 1 {
		t.Fatalf("expected 1 output, got %v", len(utxos))
	}

	// generate a second address to send the payout to
	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	// create a transaction that splits the payout
	txn := types.Transaction{
		BigfileInputs: []types.BigfileInput{
			{
				ParentID:         types.BigfileOutputID(utxos[0].ID),
				UnlockConditions: types.StandardUnlockConditions(pk.PublicKey()),
			},
		},
		BigfileOutputs: []types.BigfileOutput{
			{Address: addr2, Value: utxos[0].BigfileOutput.Value.Div64(2)},
			{Address: addr1, Value: utxos[0].BigfileOutput.Value.Div64(2)},
		},
		Signatures: []types.TransactionSignature{
			{
				ParentID:       types.Hash256(utxos[0].ID),
				PublicKeyIndex: 0,
				CoveredFields:  types.CoveredFields{WholeTransaction: true},
			},
		},
	}
	sigHash := cm.TipState().WholeSigHash(txn, types.Hash256(utxos[0].ID), 0, 0, nil)
	sig := pk.SignHash(sigHash)
	txn.Signatures[0].Signature = sig[:]

	// broadcast the transaction
	if _, err := cm.AddPoolTransactions([]types.Transaction{txn}); err != nil {
		t.Fatal(err)
	}

	// check that the unconfirmed event was recorded
	events, err := wm.WalletUnconfirmedEvents(w1.ID)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeV1Transaction {
		t.Fatalf("expected unconfirmed event, got %v", events[0].Type)
	} else if len(events[0].Relevant) != 1 {
		t.Fatalf("expected 1 relevant address, got %v", len(events[0].Relevant))
	} else if events[0].Relevant[0] != addr1 {
		t.Fatalf("expected address %v, got %v", addr1, events[0].Relevant[0])
	}

	txnData := events[0].Data.(wallet.EventV1Transaction)
	if txnData.SpentBigfileElements[0].ID != utxos[0].ID {
		t.Fatalf("expected bigfile output %v, got %v", utxos[0].ID, txnData.SpentBigfileElements[0].ID)
	} else if txnData.SpentBigfileElements[0].BigfileOutput.Value != utxos[0].BigfileOutput.Value {
		t.Fatalf("expected bigfile value %v, got %v", utxos[0].BigfileOutput.Value, txnData.SpentBigfileElements[0].BigfileOutput.Value)
	}

	// add the second address to the wallet
	if err := wm.AddAddresses(w1.ID, wallet.Address{Address: addr2}); err != nil {
		t.Fatal(err)
	}

	// check that the unconfirmed event's relevant addresses were updated
	events, err = wm.WalletUnconfirmedEvents(w1.ID)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", len(events))
	} else if len(events[0].Relevant) != 2 {
		t.Fatalf("expected 2 relevant addresses, got %v", len(events[0].Relevant))
	} else if events[0].Relevant[0] != addr1 {
		t.Fatalf("expected address %v, got %v", addr1, events[0].Relevant[0])
	} else if events[0].Relevant[1] != addr2 {
		t.Fatalf("expected address %v, got %v", addr2, events[0].Relevant[1])
	}

	// spend the ephemeral output
	ephemeralOutputID := txn.BigfileOutputID(0)
	txn2 := types.Transaction{
		BigfileInputs: []types.BigfileInput{
			{
				ParentID:         ephemeralOutputID,
				UnlockConditions: types.StandardUnlockConditions(pk2.PublicKey()),
			},
		},
		BigfileOutputs: []types.BigfileOutput{
			{Address: types.VoidAddress, Value: txn.BigfileOutputs[0].Value},
		},
		Signatures: []types.TransactionSignature{
			{
				ParentID:       types.Hash256(ephemeralOutputID),
				PublicKeyIndex: 0,
				CoveredFields:  types.CoveredFields{WholeTransaction: true},
			},
		},
	}
	sigHash = cm.TipState().WholeSigHash(txn2, txn2.Signatures[0].ParentID, 0, 0, nil)
	sig2 := pk2.SignHash(sigHash)
	txn2.Signatures[0].Signature = sig2[:]

	// broadcast the transaction
	if _, err := cm.AddPoolTransactions([]types.Transaction{txn, txn2}); err != nil {
		t.Fatal(err)
	}

	// check that the new unconfirmed event was recorded
	events, err = wm.WalletUnconfirmedEvents(w1.ID)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 2 {
		t.Fatalf("expected 2 event, got %v", len(events))
	} else if events[1].Type != wallet.EventTypeV1Transaction {
		t.Fatalf("expected unconfirmed event, got %v", events[0].Type)
	} else if len(events[1].Relevant) != 1 { // second event is only relevant to the second address
		t.Fatalf("expected 1 relevant addresses, got %v", len(events[1].Relevant))
	}

	txnData = events[1].Data.(wallet.EventV1Transaction)
	if txnData.SpentBigfileElements[0].ID != ephemeralOutputID {
		t.Fatalf("expected bigfile output %v, got %v", ephemeralOutputID, txnData.SpentBigfileElements[0].ID)
	} else if txnData.SpentBigfileElements[0].BigfileOutput.Value != txn.BigfileOutputs[0].Value {
		t.Fatalf("expected bigfile value %v, got %v", utxos[0].BigfileOutput.Value, txnData.SpentBigfileElements[0].BigfileOutput.Value)
	}

	// mine the transactions
	mineAndSync(t, cm, db, types.VoidAddress, 1)

	// check that the unconfirmed events were removed
	events, err = wm.WalletUnconfirmedEvents(w1.ID)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 0 {
		t.Fatalf("expected 0 event, got %v", len(events))
	}
}

func TestAddressUnconfirmedEvents(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	// mine a single payout to the wallet
	pk := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk.PublicKey())

	network, genesisBlock := testutil.Network()
	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	// create a wallet with no addresses
	w1, err := wm.AddWallet(wallet.Wallet{Name: "test1"})
	if err != nil {
		t.Fatal(err)
	}

	// add the address to the wallet
	if err := wm.AddAddresses(w1.ID, wallet.Address{Address: addr1}); err != nil {
		t.Fatal(err)
	}

	// mine a block sending the payout to the wallet
	mineAndSync(t, cm, db, addr1, 1)
	// mine until the payout matures
	mineAndSync(t, cm, db, types.VoidAddress, int(network.MaturityDelay))

	utxos, _, err := wm.UnspentBigfileOutputs(w1.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 1 {
		t.Fatalf("expected 1 output, got %v", len(utxos))
	}

	// generate a second address to send the payout to
	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	// create a transaction that splits the payout
	txn := types.Transaction{
		BigfileInputs: []types.BigfileInput{
			{
				ParentID:         types.BigfileOutputID(utxos[0].ID),
				UnlockConditions: types.StandardUnlockConditions(pk.PublicKey()),
			},
		},
		BigfileOutputs: []types.BigfileOutput{
			{Address: addr2, Value: utxos[0].BigfileOutput.Value.Div64(2)},
			{Address: addr1, Value: utxos[0].BigfileOutput.Value.Div64(2)},
		},
		Signatures: []types.TransactionSignature{
			{
				ParentID:       types.Hash256(utxos[0].ID),
				PublicKeyIndex: 0,
				CoveredFields:  types.CoveredFields{WholeTransaction: true},
			},
		},
	}
	sigHash := cm.TipState().WholeSigHash(txn, types.Hash256(utxos[0].ID), 0, 0, nil)
	sig := pk.SignHash(sigHash)
	txn.Signatures[0].Signature = sig[:]

	// broadcast the transaction
	if _, err := cm.AddPoolTransactions([]types.Transaction{txn}); err != nil {
		t.Fatal(err)
	}

	// check that the unconfirmed event was recorded
	events, err := wm.AddressUnconfirmedEvents(addr1)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeV1Transaction {
		t.Fatalf("expected unconfirmed event, got %v", events[0].Type)
	} else if len(events[0].Relevant) != 1 {
		t.Fatalf("expected 1 relevant address, got %v", len(events[0].Relevant))
	} else if events[0].Relevant[0] != addr1 {
		t.Fatalf("expected address %v, got %v", addr1, events[0].Relevant[0])
	}

	txnData := events[0].Data.(wallet.EventV1Transaction)
	if txnData.SpentBigfileElements[0].ID != utxos[0].ID {
		t.Fatalf("expected bigfile output %v, got %v", utxos[0].ID, txnData.SpentBigfileElements[0].ID)
	} else if txnData.SpentBigfileElements[0].BigfileOutput.Value != utxos[0].BigfileOutput.Value {
		t.Fatalf("expected bigfile value %v, got %v", utxos[0].BigfileOutput.Value, txnData.SpentBigfileElements[0].BigfileOutput.Value)
	}

	// add the second address to the wallet
	if err := wm.AddAddresses(w1.ID, wallet.Address{Address: addr2}); err != nil {
		t.Fatal(err)
	}

	// check that the address now shows an unconfirmed event
	events, err = wm.AddressUnconfirmedEvents(addr2)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", len(events))
	} else if len(events[0].Relevant) != 1 {
		t.Fatalf("expected 1 relevant addresses, got %v", len(events[0].Relevant))
	} else if events[0].Relevant[0] != addr2 {
		t.Fatalf("expected address %v, got %v", addr2, events[0].Relevant[1])
	}

	// spend the ephemeral output
	ephemeralOutputID := txn.BigfileOutputID(0)
	txn2 := types.Transaction{
		BigfileInputs: []types.BigfileInput{
			{
				ParentID:         ephemeralOutputID,
				UnlockConditions: types.StandardUnlockConditions(pk2.PublicKey()),
			},
		},
		BigfileOutputs: []types.BigfileOutput{
			{Address: types.VoidAddress, Value: txn.BigfileOutputs[0].Value},
		},
		Signatures: []types.TransactionSignature{
			{
				ParentID:       types.Hash256(ephemeralOutputID),
				PublicKeyIndex: 0,
				CoveredFields:  types.CoveredFields{WholeTransaction: true},
			},
		},
	}

	sigHash = cm.TipState().WholeSigHash(txn2, txn2.Signatures[0].ParentID, 0, 0, nil)
	sig2 := pk2.SignHash(sigHash)
	txn2.Signatures[0].Signature = sig2[:]

	// broadcast the transaction
	if _, err := cm.AddPoolTransactions([]types.Transaction{txn, txn2}); err != nil {
		t.Fatal(err)
	}

	// check that the first address still shows only one unconfirmed event
	events, err = wm.AddressUnconfirmedEvents(addr1)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", len(events))
	}

	// check that the second address now shows two unconfirmed events
	events, err = wm.AddressUnconfirmedEvents(addr2)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 2 {
		t.Fatalf("expected 2 event, got %v", len(events))
	} else if events[1].Type != wallet.EventTypeV1Transaction {
		t.Fatalf("expected unconfirmed event, got %v", events[0].Type)
	} else if len(events[1].Relevant) != 1 { // second event is only relevant to the second address
		t.Fatalf("expected 1 relevant addresses, got %v", len(events[1].Relevant))
	} else if events[1].Relevant[0] != addr2 {
		t.Fatalf("expected address %v, got %v", addr2, events[1].Relevant[0])
	}

	txnData = events[1].Data.(wallet.EventV1Transaction)
	if txnData.SpentBigfileElements[0].ID != ephemeralOutputID {
		t.Fatalf("expected bigfile output %v, got %v", ephemeralOutputID, txnData.SpentBigfileElements[0].ID)
	} else if txnData.SpentBigfileElements[0].BigfileOutput.Value != txn.BigfileOutputs[0].Value {
		t.Fatalf("expected bigfile value %v, got %v", utxos[0].BigfileOutput.Value, txnData.SpentBigfileElements[0].BigfileOutput.Value)
	}

	// mine the transactions
	mineAndSync(t, cm, db, types.VoidAddress, 1)

	// check that the unconfirmed events were removed
	events, err = wm.AddressUnconfirmedEvents(addr1)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 0 {
		t.Fatalf("expected 0 event, got %v", len(events))
	}

	events, err = wm.AddressUnconfirmedEvents(addr2)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 0 {
		t.Fatalf("expected 0 event, got %v", len(events))
	}
}

func TestV2(t *testing.T) {
	pk := types.GeneratePrivateKey()
	addr := types.StandardUnlockHash(pk.PublicKey())

	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	network, genesisBlock := testV2Network(types.VoidAddress) // don't care about bigfunds

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)
	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	w, err := wm.AddWallet(wallet.Wallet{Name: "test"})
	if err != nil {
		t.Fatal(err)
	} else if err := wm.AddAddresses(w.ID, wallet.Address{Address: addr}); err != nil {
		t.Fatal(err)
	}

	expectedPayout := cm.TipState().BlockReward()
	mineAndSync(t, cm, db, addr, 1)

	// check that the payout was received
	balance, err := db.AddressBalance(addr)
	if err != nil {
		t.Fatal(err)
	} else if !balance.ImmatureBigfiles.Equals(expectedPayout) {
		t.Fatalf("expected %v, got %v", expectedPayout, balance.ImmatureBigfiles)
	}

	// check that a payout event was recorded
	events, err := wm.WalletEvents(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeMinerPayout {
		t.Fatalf("expected payout event, got %v", events[0].Type)
	}

	// mine until the payout matures
	mineAndSync(t, cm, db, types.VoidAddress, int(network.MaturityDelay))

	// create a v2 transaction that spends the matured payout
	utxos, basis, err := wm.UnspentBigfileOutputs(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}

	bige := utxos[0]
	policy := types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk.PublicKey()))
	txn := types.V2Transaction{
		BigfileInputs: []types.V2BigfileInput{{
			Parent: bige.BigfileElement,
			SatisfiedPolicy: types.SatisfiedPolicy{
				Policy: types.SpendPolicy{Type: policy},
			},
		}},
		BigfileOutputs: []types.BigfileOutput{
			{Address: types.VoidAddress, Value: bige.BigfileOutput.Value.Sub(types.Bigfiles(100))},
			{Address: addr, Value: types.Bigfiles(100)},
		},
	}
	txn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(cm.TipState().InputSigHash(txn))}

	if _, err := cm.AddV2PoolTransactions(basis, []types.V2Transaction{txn}); err != nil {
		t.Fatal(err)
	}
	mineAndSync(t, cm, db, types.VoidAddress, 1)

	// check that the change was received
	balance, err = wm.AddressBalance(addr)
	if err != nil {
		t.Fatal(err)
	} else if !balance.Bigfiles.Equals(types.Bigfiles(100)) {
		t.Fatalf("expected %v, got %v", expectedPayout, balance.ImmatureBigfiles)
	}

	// check that a transaction event was recorded
	events, err = wm.WalletEvents(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 2 {
		t.Fatalf("expected 2 events, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeV2Transaction {
		t.Fatalf("expected transaction event, got %v", events[0].Type)
	} else if events[0].Relevant[0] != addr {
		t.Fatalf("expected address %v, got %v", addr, events[0].Relevant[0])
	}
}

func TestScanV2(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	// mine a single payout to the wallet
	pk := types.GeneratePrivateKey()
	addr := types.StandardUnlockHash(pk.PublicKey())

	network, genesisBlock := testV2Network(addr)
	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	// create a wallet with no addresses
	w, err := wm.AddWallet(wallet.Wallet{Name: "test"})
	if err != nil {
		t.Fatal(err)
	}

	// add the address to the wallet
	if err := wm.AddAddresses(w.ID, wallet.Address{Address: addr}); err != nil {
		t.Fatal(err)
	}
	// rescan to get the genesis Bigfund state
	if err := wm.Scan(context.Background(), types.ChainIndex{}); err != nil {
		t.Fatal(err)
	}

	checkBalance := func(bigfile, immature types.Currency) error {
		waitForBlock(t, cm, db)

		// note: the bigfund balance is currently hardcoded to the number of
		// bigfunds in genesis. If we ever modify this test to also spend
		// bigfunds, this will need to be updated.
		b, err := wm.WalletBalance(w.ID)
		if err != nil {
			return fmt.Errorf("failed to check balance: %w", err)
		} else if !b.Bigfiles.Equals(bigfile) {
			return fmt.Errorf("expected bigfile balance %v, got %v", bigfile, b.Bigfiles)
		} else if !b.ImmatureBigfiles.Equals(immature) {
			return fmt.Errorf("expected immature bigfile balance %v, got %v", immature, b.ImmatureBigfiles)
		} else if b.Bigfunds != network.GenesisState().BigfundCount() {
			return fmt.Errorf("expected bigfund balance %v, got %v", network.GenesisState().BigfundCount(), b.Bigfunds)
		}
		return nil
	}

	// check that the wallet has no balance
	if err := checkBalance(types.ZeroCurrency, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	expectedBalance1 := cm.TipState().BlockReward()
	// mine a block to fund the first address
	if b, ok := coreutils.MineBlock(cm, addr, 5*time.Second); !ok {
		t.Fatal("failed to mine block")
	} else if err := cm.AddBlocks([]types.Block{b}); err != nil {
		t.Fatal(err)
	}

	// mine a block to fund the second address
	expectedBalance2 := cm.TipState().BlockReward()
	if b, ok := coreutils.MineBlock(cm, addr2, 5*time.Second); !ok {
		t.Fatal("failed to mine block")
	} else if err := cm.AddBlocks([]types.Block{b}); err != nil {
		t.Fatal(err)
	}

	// check that the wallet has one immature payout
	if err := checkBalance(types.ZeroCurrency, expectedBalance1); err != nil {
		t.Fatal(err)
	}

	// mine until the first payout matures
	for i := cm.Tip().Height; i < genesisState.MaturityHeight(); i++ {
		if b, ok := coreutils.MineBlock(cm, types.VoidAddress, 5*time.Second); !ok {
			t.Fatal("failed to mine block")
		} else if err := cm.AddBlocks([]types.Block{b}); err != nil {
			t.Fatal(err)
		}
	}

	// check that the wallet balance has matured
	if err := checkBalance(expectedBalance1, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// scan for changes
	if err := wm.Scan(context.Background(), types.ChainIndex{}); err != nil {
		t.Fatal(err)
	}

	// check that the wallet balance did not change
	if err := checkBalance(expectedBalance1, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// add the second address to the wallet
	if err := wm.AddAddresses(w.ID, wallet.Address{Address: addr2}); err != nil {
		t.Fatal(err)
	} else if err := checkBalance(expectedBalance1, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// scan for changes
	if err := wm.Scan(context.Background(), types.ChainIndex{}); err != nil {
		t.Fatal(err)
	}

	if err := checkBalance(expectedBalance1, expectedBalance2); err != nil {
		t.Fatal(err)
	}

	// mine a block to mature the second payout
	if b, ok := coreutils.MineBlock(cm, types.VoidAddress, 5*time.Second); !ok {
		t.Fatal("failed to mine block")
	} else if err := cm.AddBlocks([]types.Block{b}); err != nil {
		t.Fatal(err)
	}

	// check that the wallet balance has matured
	if err := checkBalance(expectedBalance1.Add(expectedBalance2), types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// sanity check
	if err := wm.Scan(context.Background(), types.ChainIndex{}); err != nil {
		t.Fatal(err)
	}

	// check that the wallet balance has matured
	if err := checkBalance(expectedBalance1.Add(expectedBalance2), types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	utxos, basis, err := wm.AddressBigfileOutputs(addr, false, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if basis != cm.Tip() {
		t.Fatalf("expected basis to be the current tip")
	}

	// spend the payout
	bige := utxos[0]
	policy := types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk.PublicKey()))
	txn := types.V2Transaction{
		BigfileInputs: []types.V2BigfileInput{{
			Parent: bige.BigfileElement,
			SatisfiedPolicy: types.SatisfiedPolicy{
				Policy: types.SpendPolicy{Type: policy},
			},
		}},
		BigfileOutputs: []types.BigfileOutput{
			{Address: types.VoidAddress, Value: bige.BigfileOutput.Value},
		},
	}
	txn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(cm.TipState().InputSigHash(txn))}

	if _, err := cm.AddV2PoolTransactions(basis, []types.V2Transaction{txn}); err != nil {
		t.Fatal(err)
	}
	mineAndSync(t, cm, db, types.VoidAddress, 1)

	// check that the first address has a balance of zero
	if err := checkBalance(expectedBalance2, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}
}

func TestReorgV2(t *testing.T) {
	pk := types.GeneratePrivateKey()
	addr := types.StandardUnlockHash(pk.PublicKey())

	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	network, genesisBlock := testV2Network(types.VoidAddress) // don't care about bigfunds

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}
	cm := chain.NewManager(store, genesisState)

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	w, err := wm.AddWallet(wallet.Wallet{Name: "test"})
	if err != nil {
		t.Fatal(err)
	} else if err := wm.AddAddresses(w.ID, wallet.Address{Address: addr}); err != nil {
		t.Fatal(err)
	}

	expectedPayout := cm.TipState().BlockReward()
	// mine a block sending the payout to the wallet
	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, addr)}); err != nil {
		t.Fatal(err)
	}
	waitForBlock(t, cm, db)

	assertBalance := func(bigfile, immature types.Currency) error {
		b, err := wm.WalletBalance(w.ID)
		if err != nil {
			return fmt.Errorf("failed to check balance: %w", err)
		} else if !b.Bigfiles.Equals(bigfile) {
			return fmt.Errorf("expected bigfile balance %v, got %v", bigfile, b.Bigfiles)
		} else if !b.ImmatureBigfiles.Equals(immature) {
			return fmt.Errorf("expected immature bigfile balance %v, got %v", immature, b.ImmatureBigfiles)
		}
		return nil
	}

	if err := assertBalance(types.ZeroCurrency, expectedPayout); err != nil {
		t.Fatal(err)
	}

	// check that a payout event was recorded
	events, err := wm.WalletEvents(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeMinerPayout {
		t.Fatalf("expected payout event, got %v", events[0].Type)
	}

	// check that the utxo has not matured
	utxos, _, err := wm.UnspentBigfileOutputs(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 0 {
		t.Fatalf("expected no outputs, got %v", len(utxos))
	}

	// mine to trigger a reorg
	var blocks []types.Block
	state := genesisState
	for i := 0; i < 10; i++ {
		block := mineBlock(state, nil, types.VoidAddress)
		blocks = append(blocks, block)
		state.Index.ID = block.ID()
		state.Index.Height++
	}
	if err := cm.AddBlocks(blocks); err != nil {
		t.Fatal(err)
	}
	waitForBlock(t, cm, db)

	// check that the balance was reverted
	if err := assertBalance(types.ZeroCurrency, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// check that the payout event was reverted
	events, err = wm.WalletEvents(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 0 {
		t.Fatalf("expected 0 events, got %v", len(events))
	}

	// check that the utxo was removed
	utxos, _, err = wm.UnspentBigfileOutputs(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 0 {
		t.Fatalf("expected 0 outputs, got %v", len(utxos))
	}

	// mine a new payout
	expectedPayout = cm.TipState().BlockReward()
	maturityHeight := cm.TipState().MaturityHeight()
	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, addr)}); err != nil {
		t.Fatal(err)
	}
	waitForBlock(t, cm, db)

	// check that the payout was received
	if err := assertBalance(types.ZeroCurrency, expectedPayout); err != nil {
		t.Fatal(err)
	}

	// check that a payout event was recorded
	events, err = wm.WalletEvents(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeMinerPayout {
		t.Fatalf("expected payout event, got %v", events[0].Type)
	}

	// check that the utxo has not matured
	utxos, _, err = wm.UnspentBigfileOutputs(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 0 {
		t.Fatalf("expected no outputs, got %v", len(utxos))
	}

	// mine until the payout matures
	var prevState consensus.State
	for i := cm.TipState().Index.Height; i < maturityHeight+1; i++ {
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
		if i == maturityHeight-5 {
			prevState = cm.TipState()
		}
	}
	waitForBlock(t, cm, db)

	// check that the balance was updated
	if err := assertBalance(expectedPayout, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// reorg the last few blocks to re-mature the payout
	blocks = nil
	state = prevState
	for i := 0; i < 10; i++ {
		blocks = append(blocks, mineBlock(state, nil, types.VoidAddress))
		state.Index.ID = blocks[len(blocks)-1].ID()
		state.Index.Height++
	}
	if err := cm.AddBlocks(blocks); err != nil {
		t.Fatal(err)
	}
	waitForBlock(t, cm, db)

	// check that the balance is correct
	if err := assertBalance(expectedPayout, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// check that only the single utxo still exists
	utxos, _, err = wm.UnspentBigfileOutputs(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 1 {
		t.Fatalf("expected 1 output, got %v", len(utxos))
	} else if utxos[0].BigfileOutput.Value.Cmp(expectedPayout) != 0 {
		t.Fatalf("expected %v, got %v", expectedPayout, utxos[0].BigfileOutput.Value)
	} else if utxos[0].MaturityHeight != maturityHeight {
		t.Fatalf("expected %v, got %v", maturityHeight, utxos[0].MaturityHeight)
	}

	// spend the payout
	bige := utxos[0]
	policy := types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk.PublicKey()))
	txn := types.V2Transaction{
		BigfileInputs: []types.V2BigfileInput{{
			Parent: bige.BigfileElement,
			SatisfiedPolicy: types.SatisfiedPolicy{
				Policy: types.SpendPolicy{Type: policy},
			},
		}},
		BigfileOutputs: []types.BigfileOutput{
			{Address: types.VoidAddress, Value: bige.BigfileOutput.Value},
		},
	}
	txn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(cm.TipState().InputSigHash(txn))}

	if err := cm.AddBlocks([]types.Block{mineV2Block(cm.TipState(), []types.V2Transaction{txn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	waitForBlock(t, cm, db)

	// check that the balance is correct
	if err := assertBalance(types.ZeroCurrency, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// check that all UTXOs have been spent
	utxos, _, err = wm.UnspentBigfileOutputs(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 0 {
		t.Fatalf("expected 0 output, got %v", len(utxos))
	}
}

func TestOrphansV2(t *testing.T) {
	pk := types.GeneratePrivateKey()
	addr := types.StandardUnlockHash(pk.PublicKey())

	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	network, genesisBlock := testV2Network(types.VoidAddress) // don't care about bigfunds
	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}
	cm := chain.NewManager(store, genesisState)

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	w, err := wm.AddWallet(wallet.Wallet{Name: "test"})
	if err != nil {
		t.Fatal(err)
	} else if err := wm.AddAddresses(w.ID, wallet.Address{Address: addr}); err != nil {
		t.Fatal(err)
	}

	expectedPayout := cm.TipState().BlockReward()
	maturityHeight := cm.TipState().MaturityHeight()
	// mine a block sending the payout to the wallet
	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, addr)}); err != nil {
		t.Fatal(err)
	}

	// mine until the maturity height
	for i := cm.TipState().Index.Height; i < maturityHeight+1; i++ {
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
	}
	waitForBlock(t, cm, db)

	assertBalance := func(bigfile, immature types.Currency) error {
		b, err := wm.WalletBalance(w.ID)
		if err != nil {
			return fmt.Errorf("failed to check balance: %w", err)
		} else if !b.ImmatureBigfiles.Equals(immature) {
			return fmt.Errorf("expected immature bigfile balance %v, got %v", immature, b.ImmatureBigfiles)
		} else if !b.Bigfiles.Equals(bigfile) {
			return fmt.Errorf("expected bigfile balance %v, got %v", bigfile, b.Bigfiles)
		}
		return nil
	}

	if err := assertBalance(expectedPayout, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// check that a payout event was recorded
	events, err := wm.WalletEvents(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", len(events))
	} else if events[0].Type != wallet.EventTypeMinerPayout {
		t.Fatalf("expected payout event, got %v", events[0].Type)
	}

	// check that the utxo was created
	utxos, _, err := wm.UnspentBigfileOutputs(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 1 {
		t.Fatalf("expected 1 output, got %v", len(utxos))
	} else if utxos[0].BigfileOutput.Value.Cmp(expectedPayout) != 0 {
		t.Fatalf("expected %v, got %v", expectedPayout, utxos[0].BigfileOutput.Value)
	} else if utxos[0].MaturityHeight != maturityHeight {
		t.Fatalf("expected %v, got %v", maturityHeight, utxos[0].MaturityHeight)
	}

	resetState := cm.TipState()

	// send a transaction that will be orphaned
	bige := utxos[0]
	policy := types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk.PublicKey()))
	txn := types.V2Transaction{
		BigfileInputs: []types.V2BigfileInput{{
			Parent: bige.BigfileElement,
			SatisfiedPolicy: types.SatisfiedPolicy{
				Policy: types.SpendPolicy{Type: policy},
			},
		}},
		BigfileOutputs: []types.BigfileOutput{
			{Address: types.VoidAddress, Value: expectedPayout.Div64(2)}, // send the other half to the void
			{Address: addr, Value: expectedPayout.Div64(2)},              // send half the payout back to the wallet
		},
	}
	txn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(cm.TipState().InputSigHash(txn))}

	// broadcast the transaction
	if err := cm.AddBlocks([]types.Block{mineV2Block(cm.TipState(), []types.V2Transaction{txn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	waitForBlock(t, cm, db)

	if err := assertBalance(expectedPayout.Div64(2), types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// check that the transaction event was recorded
	events, err = wm.WalletEvents(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 2 {
		t.Fatalf("expected 2 events, got %v", len(events))
	}

	// simulate an interrupted rescan by closing the wallet manager, resetting the
	// last scan index, and initializing a new wallet manager.
	if err := wm.Close(); err != nil {
		t.Fatal(err)
	} else if err := db.ResetLastIndex(); err != nil {
		t.Fatal(err)
	}

	// mine to trigger a reorg. The underlying store must properly revert the
	// orphaned blocks that will not be cleanly reverted since the rescan was
	// interrupted.
	var blocks []types.Block
	state := resetState
	for i := 0; i < 5; i++ {
		blocks = append(blocks, mineBlock(state, nil, types.VoidAddress))
		state.Index.ID = blocks[len(blocks)-1].ID()
		state.Index.Height++
	}
	if err := cm.AddBlocks(blocks); err != nil {
		t.Fatal(err)
	}

	wm, err = wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	waitForBlock(t, cm, db)

	// check that the transaction was reverted
	if err := assertBalance(expectedPayout, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// check that the transaction event was reverted
	events, err = wm.WalletEvents(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 1 {
		t.Fatalf("expected 1 event, got %v", len(events))
	}

	// check that the utxo was reverted
	utxos, _, err = wm.UnspentBigfileOutputs(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 1 {
		t.Fatalf("expected 1 output, got %v", len(utxos))
	} else if !utxos[0].BigfileOutput.Value.Equals(expectedPayout) {
		t.Fatalf("expected %v, got %v", expectedPayout, utxos[0].BigfileOutput.Value)
	}

	// spend the payout
	txn = types.V2Transaction{
		BigfileInputs: []types.V2BigfileInput{{
			Parent: bige.BigfileElement,
			SatisfiedPolicy: types.SatisfiedPolicy{
				Policy: types.SpendPolicy{Type: policy},
			},
		}},
		BigfileOutputs: []types.BigfileOutput{
			{Address: types.VoidAddress, Value: bige.BigfileOutput.Value},
		},
	}
	txn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(cm.TipState().InputSigHash(txn))}

	if err := cm.AddBlocks([]types.Block{mineV2Block(cm.TipState(), []types.V2Transaction{txn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	waitForBlock(t, cm, db)

	// check that the balance is correct
	if err := assertBalance(types.ZeroCurrency, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	// check that all UTXOs have been spent
	utxos, _, err = wm.UnspentBigfileOutputs(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 0 {
		t.Fatalf("expected 0 output, got %v", len(utxos))
	}
}

func TestDeleteWallet(t *testing.T) {
	pk := types.GeneratePrivateKey()
	addr := types.StandardUnlockHash(pk.PublicKey())

	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	network, genesisBlock := testV1Network(types.VoidAddress) // don't care about bigfunds

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}
	cm := chain.NewManager(store, genesisState)

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	w, err := wm.AddWallet(wallet.Wallet{Name: "test"})
	if err != nil {
		t.Fatal(err)
	} else if err := wm.AddAddresses(w.ID, wallet.Address{Address: addr}); err != nil {
		t.Fatal(err)
	}

	if err := wm.DeleteWallet(w.ID); err != nil {
		t.Fatal(err)
	}
}

// NOTE: due to a bug in the transaction validation code, calculating payouts
// is way harder than it needs to be. Tax is calculated on the post-tax
// contract payout (instead of the sum of the renter and host payouts). So the
// equation for the payout is:
//
//	   payout = renterPayout + hostPayout + payout*tax
//	∴  payout = (renterPayout + hostPayout) / (1 - tax)
//
// This would work if 'tax' were a simple fraction, but because the tax must
// be evenly distributed among bigfund holders, 'tax' is actually a function
// that multiplies by a fraction and then rounds down to the nearest multiple
// of the bigfund count. Thus, when inverting the function, we have to make an
// initial guess and then fix the rounding error.
func taxAdjustedPayout(target types.Currency) types.Currency {
	// compute initial guess as target * (1 / 1-tax); since this does not take
	// the bigfund rounding into account, the guess will be up to
	// types.BigfundCount greater than the actual payout value.
	guess := target.Mul64(1000).Div64(961)

	// now, adjust the guess to remove the rounding error. We know that:
	//
	//   (target % types.BigfundCount) == (payout % types.BigfundCount)
	//
	// therefore, we can simply adjust the guess to have this remainder as
	// well. The only wrinkle is that, since we know guess >= payout, if the
	// guess remainder is smaller than the target remainder, we must subtract
	// an extra types.BigfundCount.
	//
	// for example, if target = 87654321 and types.BigfundCount = 10000, then:
	//
	//   initial_guess  = 87654321 * (1 / (1 - tax))
	//                  = 91211572
	//   target % 10000 =     4321
	//   adjusted_guess = 91204321

	mod64 := func(c types.Currency, v uint64) types.Currency {
		var r uint64
		if c.Hi < v {
			_, r = bits.Div64(c.Hi, c.Lo, v)
		} else {
			_, r = bits.Div64(0, c.Hi, v)
			_, r = bits.Div64(r, c.Lo, v)
		}
		return types.NewCurrency64(r)
	}
	sfc := (consensus.State{}).BigfundCount()
	tm := mod64(target, sfc)
	gm := mod64(guess, sfc)
	if gm.Cmp(tm) < 0 {
		guess = guess.Sub(types.NewCurrency64(sfc))
	}
	return guess.Add(tm).Sub(gm)
}

func TestEventTypes(t *testing.T) {
	pk := types.GeneratePrivateKey()
	addr := types.StandardUnlockHash(pk.PublicKey())

	log := zap.NewNop()
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	// create a new test network with the Bigfund airdrop going to the wallet address
	network, genesisBlock := testV2Network(addr)
	// raise the require height to test v1 events
	network.HardforkV2.RequireHeight = 250
	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}
	cm := chain.NewManager(store, genesisState)

	// helper to mine blocks
	mineBlock := func(n int, addr types.Address) {
		t.Helper()
		for i := 0; i < n; i++ {
			b, ok := coreutils.MineBlock(cm, addr, 15*time.Second)
			if !ok {
				t.Fatal("failed to mine block")
			} else if err := cm.AddBlocks([]types.Block{b}); err != nil {
				t.Fatal(err)
			}
		}
		waitForBlock(t, cm, db)
	}

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")), wallet.WithIndexMode(wallet.IndexModeFull))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	spendableBigfileUTXOs := func(t *testing.T) ([]wallet.UnspentBigfileElement, types.ChainIndex) {
		t.Helper()

		biges, basis, err := wm.AddressBigfileOutputs(addr, false, 0, 100)
		if err != nil {
			t.Fatal(err)
		} else if basis != cm.Tip() {
			t.Fatalf("expected basis to be the current tip")
		}
		filtered := biges[:0]
		height := cm.Tip().Height
		for _, bige := range biges {
			if bige.MaturityHeight > height {
				continue
			}
			filtered = append(filtered, bige)
		}
		sort.Slice(filtered, func(i, j int) bool {
			return filtered[i].BigfileOutput.Value.Cmp(filtered[j].BigfileOutput.Value) < 0
		})
		return filtered, basis
	}

	assertEvent := func(t *testing.T, id types.Hash256, eventType string, expectedInflow, expectedOutflow types.Currency, maturityHeight uint64) {
		t.Helper()

		events, err := wm.AddressEvents(addr, 0, 100)
		if err != nil {
			t.Fatal(err)
		}

		for _, event := range events {
			if event.ID == id {
				if event.Type != eventType {
					t.Fatalf("expected %v event, got %v", eventType, event.Type)
				} else if event.MaturityHeight != maturityHeight {
					t.Fatalf("expected maturity height %v, got %v", maturityHeight, event.MaturityHeight)
				}

				if !event.BigfileInflow().Equals(expectedInflow) {
					t.Fatalf("expected inflow %v, got %v", expectedInflow, event.BigfileInflow())
				} else if !event.BigfileOutflow().Equals(expectedOutflow) {
					t.Fatalf("expected outflow %v, got %v", expectedOutflow, event.BigfileOutflow())
				}
				return
			}
		}
		t.Fatalf("event not found")
	}

	// miner payout event
	mineBlock(1, addr)
	assertEvent(t, types.Hash256(cm.Tip().ID.MinerOutputID(0)), wallet.EventTypeMinerPayout, genesisState.BlockReward(), types.ZeroCurrency, genesisState.MaturityHeight())

	// mine until the payout matures
	mineBlock(int(cm.TipState().MaturityHeight()), types.VoidAddress)

	// v1 transaction
	t.Run("v1 transaction", func(t *testing.T) {
		bige, _ := spendableBigfileUTXOs(t)

		// v1 only supports unlock conditions
		uc := types.StandardUnlockConditions(pk.PublicKey())

		// create a transaction
		txn := types.Transaction{
			BigfileInputs: []types.BigfileInput{
				{ParentID: types.BigfileOutputID(bige[0].ID), UnlockConditions: uc},
			},
			BigfileOutputs: []types.BigfileOutput{
				{Address: types.VoidAddress, Value: types.Bigfiles(1000)},
				{Address: addr, Value: bige[0].BigfileOutput.Value.Sub(types.Bigfiles(1000))},
			},
			Signatures: []types.TransactionSignature{
				{
					ParentID:       types.Hash256(bige[0].ID),
					PublicKeyIndex: 0,
					Timelock:       0,
					CoveredFields:  types.CoveredFields{WholeTransaction: true},
				},
			},
		}

		// sign the transaction
		sigHash := cm.TipState().WholeSigHash(txn, types.Hash256(bige[0].ID), 0, 0, nil)
		sig := pk.SignHash(sigHash)
		txn.Signatures[0].Signature = sig[:]

		// broadcast the transaction
		if _, err := cm.AddPoolTransactions([]types.Transaction{txn}); err != nil {
			t.Fatal(err)
		}
		// mine a block to confirm the transaction
		mineBlock(1, types.VoidAddress)
		assertEvent(t, types.Hash256(txn.ID()), wallet.EventTypeV1Transaction, bige[0].BigfileOutput.Value.Sub(types.Bigfiles(1000)), bige[0].BigfileOutput.Value, cm.Tip().Height)
	})

	t.Run("v1 contract resolution - missed", func(t *testing.T) {
		// v1 contract resolution - only one type of resolution is supported.
		// The only difference is `missed == true` or `missed == false`

		bige, _ := spendableBigfileUTXOs(t)
		uc := types.StandardUnlockConditions(pk.PublicKey())

		// create a storage contract
		contractPayout := types.Bigfiles(10000)
		fc := types.FileContract{
			WindowStart: cm.TipState().Index.Height + 10,
			WindowEnd:   cm.TipState().Index.Height + 20,
			Payout:      taxAdjustedPayout(contractPayout),
			ValidProofOutputs: []types.BigfileOutput{
				{Address: addr, Value: contractPayout},
			},
			MissedProofOutputs: []types.BigfileOutput{
				{Address: addr, Value: contractPayout},
			},
		}

		// create a transaction with the contract
		txn := types.Transaction{
			BigfileInputs: []types.BigfileInput{
				{ParentID: types.BigfileOutputID(bige[0].ID), UnlockConditions: uc},
			},
			BigfileOutputs: []types.BigfileOutput{
				{Address: addr, Value: bige[0].BigfileOutput.Value.Sub(fc.Payout)}, // return the remainder to the wallet
			},
			FileContracts: []types.FileContract{fc},
			Signatures: []types.TransactionSignature{
				{
					ParentID:       types.Hash256(bige[0].ID),
					PublicKeyIndex: 0,
					Timelock:       0,
					CoveredFields:  types.CoveredFields{WholeTransaction: true},
				},
			},
		}
		sigHash := cm.TipState().WholeSigHash(txn, types.Hash256(bige[0].ID), 0, 0, nil)
		sig := pk.SignHash(sigHash)
		txn.Signatures[0].Signature = sig[:]

		// broadcast the transaction
		if _, err := cm.AddPoolTransactions([]types.Transaction{txn}); err != nil {
			t.Fatal(err)
		}

		txn.FileContractID(0).MissedOutputID(0)

		// mine a block to confirm the transaction
		mineBlock(1, types.VoidAddress)
		// mine until the contract expires to trigger the resolution event
		blocksRemaining := int(fc.WindowEnd - cm.Tip().Height)
		mineBlock(blocksRemaining, types.VoidAddress)
		assertEvent(t, types.Hash256(txn.FileContractID(0).MissedOutputID(0)), wallet.EventTypeV1ContractResolution, contractPayout, types.ZeroCurrency, fc.WindowEnd+144)
	})

	t.Run("v2 transaction", func(t *testing.T) {
		bige, basis := spendableBigfileUTXOs(t)

		// using the UnlockConditions policy for brevity
		policy := types.SpendPolicy{
			Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk.PublicKey())),
		}

		txn := types.V2Transaction{
			BigfileInputs: []types.V2BigfileInput{
				{
					Parent: bige[0].BigfileElement,
					SatisfiedPolicy: types.SatisfiedPolicy{
						Policy: policy,
					},
				},
			},
			BigfileOutputs: []types.BigfileOutput{
				{Address: types.VoidAddress, Value: types.Bigfiles(1000)},
				{Address: addr, Value: bige[0].BigfileOutput.Value.Sub(types.Bigfiles(1000))},
			},
		}
		sigHash := cm.TipState().InputSigHash(txn)
		txn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(sigHash)}

		// broadcast the transaction
		if _, err := cm.AddV2PoolTransactions(basis, []types.V2Transaction{txn}); err != nil {
			t.Fatal(err)
		}
		// mine a block to confirm the transaction
		mineBlock(1, types.VoidAddress)
		assertEvent(t, types.Hash256(txn.ID()), wallet.EventTypeV2Transaction, bige[0].BigfileOutput.Value.Sub(types.Bigfiles(1000)), bige[0].BigfileOutput.Value, cm.Tip().Height)
	})

	t.Run("v2 contract resolution - expired", func(t *testing.T) {
		bige, basis := spendableBigfileUTXOs(t)

		// using the UnlockConditions policy for brevity
		policy := types.SpendPolicy{
			Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk.PublicKey())),
		}

		// create a storage contract
		renterPayout := types.Bigfiles(10000)
		fc := types.V2FileContract{
			RenterOutput: types.BigfileOutput{
				Address: addr,
				Value:   renterPayout,
			},
			HostOutput: types.BigfileOutput{
				Address: types.VoidAddress,
				Value:   types.ZeroCurrency,
			},
			ProofHeight:      cm.TipState().Index.Height + 10,
			ExpirationHeight: cm.TipState().Index.Height + 20,

			RenterPublicKey: pk.PublicKey(),
			HostPublicKey:   pk.PublicKey(),
		}
		contractValue := renterPayout.Add(cm.TipState().V2FileContractTax(fc))
		sigHash := cm.TipState().ContractSigHash(fc)
		sig := pk.SignHash(sigHash)
		fc.RenterSignature = sig
		fc.HostSignature = sig

		// create a transaction with the contract
		txn := types.V2Transaction{
			FileContracts: []types.V2FileContract{fc},
			BigfileInputs: []types.V2BigfileInput{
				{
					Parent: bige[0].BigfileElement,
					SatisfiedPolicy: types.SatisfiedPolicy{
						Policy: policy,
					},
				},
			},
			BigfileOutputs: []types.BigfileOutput{
				{Address: addr, Value: bige[0].BigfileOutput.Value.Sub(contractValue)},
			},
		}
		sigHash = cm.TipState().InputSigHash(txn)
		txn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(sigHash)}

		// broadcast the transaction
		if _, err := cm.AddV2PoolTransactions(basis, []types.V2Transaction{txn}); err != nil {
			t.Fatal(err)
		}
		// current tip
		tip := cm.Tip()
		// mine until the contract expires
		mineBlock(int(fc.ExpirationHeight-cm.Tip().Height), types.VoidAddress)

		// this is kind of annoying because we have to keep the file contract
		// proof up to date.
		_, applied, err := cm.UpdatesSince(tip, 1000)
		if err != nil {
			t.Fatal(err)
		}

		// get the confirmed file contract element
		fce := applied[0].V2FileContractElementDiffs()[0].V2FileContractElement
		for _, cau := range applied[1:] {
			cau.UpdateElementProof(&fce.StateElement)
		}

		resolutionTxn := types.V2Transaction{
			FileContractResolutions: []types.V2FileContractResolution{
				{
					Parent:     fce,
					Resolution: &types.V2FileContractExpiration{},
				},
			},
		}
		// broadcast the expire resolution
		if _, err := cm.AddV2PoolTransactions(cm.Tip(), []types.V2Transaction{resolutionTxn}); err != nil {
			t.Fatal(err)
		}
		// mine a block to confirm the resolution
		mineBlock(1, types.VoidAddress)
		assertEvent(t, types.Hash256(types.FileContractID(fce.ID).V2RenterOutputID()), wallet.EventTypeV2ContractResolution, renterPayout, types.ZeroCurrency, cm.Tip().Height+144)
	})

	t.Run("v2 contract resolution - storage proof", func(t *testing.T) {
		bige, basis := spendableBigfileUTXOs(t)

		// using the UnlockConditions policy for brevity
		policy := types.SpendPolicy{
			Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk.PublicKey())),
		}

		// create a storage contract
		renterPayout := types.Bigfiles(10000)
		fc := types.V2FileContract{
			RenterOutput: types.BigfileOutput{
				Address: types.VoidAddress,
				Value:   types.ZeroCurrency,
			},
			HostOutput: types.BigfileOutput{
				Address: addr,
				Value:   renterPayout,
			},
			ProofHeight:      cm.TipState().Index.Height + 10,
			ExpirationHeight: cm.TipState().Index.Height + 20,

			RenterPublicKey: pk.PublicKey(),
			HostPublicKey:   pk.PublicKey(),
		}
		contractValue := renterPayout.Add(cm.TipState().V2FileContractTax(fc))
		sigHash := cm.TipState().ContractSigHash(fc)
		sig := pk.SignHash(sigHash)
		fc.RenterSignature = sig
		fc.HostSignature = sig

		// create a transaction with the contract
		txn := types.V2Transaction{
			FileContracts: []types.V2FileContract{fc},
			BigfileInputs: []types.V2BigfileInput{
				{
					Parent: bige[0].BigfileElement,
					SatisfiedPolicy: types.SatisfiedPolicy{
						Policy: policy,
					},
				},
			},
			BigfileOutputs: []types.BigfileOutput{
				{Address: addr, Value: bige[0].BigfileOutput.Value.Sub(contractValue)},
			},
		}
		sigHash = cm.TipState().InputSigHash(txn)
		txn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(sigHash)}

		// broadcast the transaction
		if _, err := cm.AddV2PoolTransactions(basis, []types.V2Transaction{txn}); err != nil {
			t.Fatal(err)
		}
		// current tip
		tip := cm.Tip()
		// mine until the contract proof window
		mineBlock(int(fc.ProofHeight-cm.Tip().Height), types.VoidAddress)

		// this is even more annoying because we have to keep the file contract
		// proof and the chain index proof up to date.
		_, applied, err := cm.UpdatesSince(tip, 1000)
		if err != nil {
			t.Fatal(err)
		}

		// get the confirmed file contract element
		fce := applied[0].V2FileContractElementDiffs()[0].V2FileContractElement
		for _, cau := range applied[1:] {
			cau.UpdateElementProof(&fce.StateElement)
		}
		// get the proof index element
		indexElement := applied[len(applied)-1].ChainIndexElement()

		resolutionTxn := types.V2Transaction{
			FileContractResolutions: []types.V2FileContractResolution{
				{
					Parent: fce,
					Resolution: &types.V2StorageProof{
						ProofIndex: indexElement,
						// proof is nil since there's no data
					},
				},
			},
		}

		// broadcast the expire resolution
		if _, err := cm.AddV2PoolTransactions(cm.Tip(), []types.V2Transaction{resolutionTxn}); err != nil {
			t.Fatal(err)
		}
		mineBlock(1, types.VoidAddress)
		assertEvent(t, types.Hash256(types.FileContractID(fce.ID).V2HostOutputID()), wallet.EventTypeV2ContractResolution, renterPayout, types.ZeroCurrency, cm.Tip().Height+144)
	})

	t.Run("v2 contract resolution - renewal", func(t *testing.T) {
		biges, basis := spendableBigfileUTXOs(t)

		// using the UnlockConditions policy for brevity
		policy := types.SpendPolicy{
			Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk.PublicKey())),
		}

		// create a storage contract
		renterPayout := types.Bigfiles(10000)
		fc := types.V2FileContract{
			RenterOutput: types.BigfileOutput{
				Address: addr,
				Value:   renterPayout,
			},
			HostOutput: types.BigfileOutput{
				Address: types.VoidAddress,
				Value:   types.ZeroCurrency,
			},
			ProofHeight:      cm.TipState().Index.Height + 10,
			ExpirationHeight: cm.TipState().Index.Height + 20,

			RenterPublicKey: pk.PublicKey(),
			HostPublicKey:   pk.PublicKey(),
		}
		contractValue := renterPayout.Add(cm.TipState().V2FileContractTax(fc))
		sigHash := cm.TipState().ContractSigHash(fc)
		sig := pk.SignHash(sigHash)
		fc.RenterSignature = sig
		fc.HostSignature = sig

		// create a transaction with the contract
		txn := types.V2Transaction{
			FileContracts: []types.V2FileContract{fc},
			BigfileInputs: []types.V2BigfileInput{
				{
					Parent: biges[0].BigfileElement,
					SatisfiedPolicy: types.SatisfiedPolicy{
						Policy: policy,
					},
				},
			},
			BigfileOutputs: []types.BigfileOutput{
				{Address: addr, Value: biges[0].BigfileOutput.Value.Sub(contractValue)},
			},
		}
		sigHash = cm.TipState().InputSigHash(txn)
		txn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(sigHash)}

		// broadcast the transaction
		if _, err := cm.AddV2PoolTransactions(basis, []types.V2Transaction{txn}); err != nil {
			t.Fatal(err)
		}
		// current tip
		tip := cm.Tip()
		// mine until the contract proof window
		mineBlock(1, types.VoidAddress)

		// this is even more annoying because we have to keep the file contract
		// proof and the chain index proof up to date.
		_, applied, err := cm.UpdatesSince(tip, 1000)
		if err != nil {
			t.Fatal(err)
		}

		// get the confirmed file contract element
		fce := applied[0].V2FileContractElementDiffs()[0].V2FileContractElement
		for _, cau := range applied[1:] {
			cau.UpdateElementProof(&fce.StateElement)
		}

		// create a renewal
		renewal := types.V2FileContractRenewal{
			FinalHostOutput:   fc.HostOutput,
			FinalRenterOutput: fc.RenterOutput,
			NewContract: types.V2FileContract{
				RenterOutput:     fc.RenterOutput,
				ProofHeight:      fc.ProofHeight + 10,
				ExpirationHeight: fc.ExpirationHeight + 10,

				RenterPublicKey: fc.RenterPublicKey,
				HostPublicKey:   fc.HostPublicKey,
			},
		}

		renewalSigHash := cm.TipState().RenewalSigHash(renewal)
		renewalSig := pk.SignHash(renewalSigHash)
		renewal.RenterSignature = renewalSig
		renewal.HostSignature = renewalSig
		contractSigHash := cm.TipState().ContractSigHash(renewal.NewContract)
		renewal.NewContract.RenterSignature = pk.SignHash(contractSigHash)
		renewal.NewContract.HostSignature = pk.SignHash(contractSigHash)

		biges, basis = spendableBigfileUTXOs(t)
		newContractValue := renterPayout.Add(cm.TipState().V2FileContractTax(renewal.NewContract))

		// create the renewal transaction
		resolutionTxn := types.V2Transaction{
			BigfileInputs: []types.V2BigfileInput{
				{
					Parent: biges[0].BigfileElement,
					SatisfiedPolicy: types.SatisfiedPolicy{
						Policy: policy,
					},
				},
			},
			BigfileOutputs: []types.BigfileOutput{
				{Address: addr, Value: biges[0].BigfileOutput.Value.Sub(newContractValue)},
			},
			FileContractResolutions: []types.V2FileContractResolution{
				{
					Parent:     fce,
					Resolution: &renewal,
				},
			},
		}
		resolutionTxnSigHash := cm.TipState().InputSigHash(resolutionTxn)
		resolutionTxn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(resolutionTxnSigHash)}

		// broadcast the renewal
		if _, err := cm.AddV2PoolTransactions(basis, []types.V2Transaction{resolutionTxn}); err != nil {
			t.Fatal(err)
		}
		mineBlock(1, types.VoidAddress)
		assertEvent(t, types.Hash256(types.FileContractID(fce.ID).V2RenterOutputID()), wallet.EventTypeV2ContractResolution, renterPayout, types.ZeroCurrency, cm.Tip().Height+144)
	})

	t.Run("bigfund claim", func(t *testing.T) {
		bfe, basis, err := wm.AddressBigfundOutputs(addr, false, 0, 100)
		if err != nil {
			t.Fatal(err)
		} else if basis != cm.Tip() {
			t.Fatalf("expected basis to be the current tip")
		}

		policy := types.SpendPolicy{
			Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk.PublicKey())),
		}

		// create a transaction
		txn := types.V2Transaction{
			BigfundInputs: []types.V2BigfundInput{
				{
					Parent: bfe[0].BigfundElement,
					SatisfiedPolicy: types.SatisfiedPolicy{
						Policy: policy,
					},
					ClaimAddress: addr,
				},
			},
			BigfundOutputs: []types.BigfundOutput{
				{Address: addr, Value: bfe[0].BigfundOutput.Value},
			},
		}
		sigHash := cm.TipState().InputSigHash(txn)
		txn.BigfundInputs[0].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(sigHash)}
		claimValue := cm.TipState().BigfundTaxRevenue

		// broadcast the transaction
		if _, err := cm.AddV2PoolTransactions(basis, []types.V2Transaction{txn}); err != nil {
			t.Fatal(err)
		}
		// mine a block to confirm the transaction
		mineBlock(1, types.VoidAddress)
		assertEvent(t, types.Hash256(types.BigfundOutputID(bfe[0].ID).V2ClaimOutputID()), wallet.EventTypeBigfundClaim, claimValue, types.ZeroCurrency, cm.Tip().Height+144)
	})
}

func TestBigfundClaims(t *testing.T) {
	pk := types.GeneratePrivateKey()
	addr := types.StandardUnlockHash(pk.PublicKey())

	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	network, genesis := testutil.Network()
	// send the bigfunds to the owned address
	genesis.Transactions[0].BigfundOutputs[0].Address = addr
	bigfundValue := genesis.Transactions[0].BigfundOutputs[0].Value

	store, genesisState, err := chain.NewDBStore(bdb, network, genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	cm := chain.NewManager(store, genesisState)

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	w, err := wm.AddWallet(wallet.Wallet{Name: "test"})
	if err != nil {
		t.Fatal(err)
	}

	uc := types.StandardUnlockConditions(pk.PublicKey())
	err = wm.AddAddresses(w.ID, wallet.Address{
		Address: addr,
		SpendPolicy: &types.SpendPolicy{
			Type: types.PolicyTypeUnlockConditions(uc),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// rescan to index the genesis block
	if err := wm.Scan(context.Background(), types.ChainIndex{}); err != nil {
		t.Fatal(err)
	}

	// claim the bigfunds. Since tax revenue is 0, no claim event or utxo should be indexed.
	bigfunds, _, change, err := wm.SelectBigfundElements(w.ID, bigfundValue)
	if err != nil {
		t.Fatal(err)
	} else if change != 0 {
		t.Fatalf("expected no change, got %v", change)
	}
	txn := types.Transaction{
		BigfundOutputs: []types.BigfundOutput{
			{Address: addr, Value: bigfundValue},
		},
	}
	for _, bfe := range bigfunds {
		txn.BigfundInputs = append(txn.BigfundInputs, types.BigfundInput{
			ParentID:         bfe.ID,
			UnlockConditions: uc,
			ClaimAddress:     addr,
		})
		txn.Signatures = append(txn.Signatures, types.TransactionSignature{
			ParentID:      types.Hash256(bfe.ID),
			CoveredFields: types.CoveredFields{WholeTransaction: true},
		})
	}
	cs := cm.TipState()
	for i, sig := range txn.Signatures {
		sigHash := cs.WholeSigHash(txn, sig.ParentID, 0, 0, nil)
		sig := pk.SignHash(sigHash)
		txn.Signatures[i].Signature = sig[:]
	}
	if _, err := cm.AddPoolTransactions([]types.Transaction{txn}); err != nil {
		t.Fatal(err)
	}
	testutil.MineBlocks(t, cm, types.VoidAddress, 1)
	waitForBlock(t, cm, db)

	bigfiles, _, err := wm.UnspentBigfileOutputs(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(bigfiles) != 0 {
		t.Fatalf("expected no bigfile outputs, got %v", bigfiles)
	}

	events, err := wm.WalletEvents(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 2 { // airdrop + bigfund transaction
		t.Fatalf("expected 2 events, got %v", len(events))
	}

	// fund the wallet with some bigfiles
	testutil.MineBlocks(t, cm, addr, 5)
	testutil.MineBlocks(t, cm, types.VoidAddress, int(network.MaturityDelay))
	waitForBlock(t, cm, db)

	payout := types.Bigfiles(100000)
	fundAmount := taxAdjustedPayout(payout)
	expectedTaxRevenue := fundAmount.Sub(payout)
	fc := types.FileContract{
		UnlockHash: addr,
		Payout:     fundAmount,
		ValidProofOutputs: []types.BigfileOutput{
			{Address: types.VoidAddress, Value: payout},
		},
		MissedProofOutputs: []types.BigfileOutput{
			{Address: types.VoidAddress, Value: payout},
		},
		WindowStart: cm.Tip().Height + 10,
		WindowEnd:   cm.Tip().Height + 20,
	}

	fcTxn := types.Transaction{
		FileContracts: []types.FileContract{fc},
	}

	bigfiles, _, scChange, err := wm.SelectBigfileElements(w.ID, fundAmount, false)
	if err != nil {
		t.Fatal(err)
	}

	if !scChange.IsZero() {
		fcTxn.BigfileOutputs = append(fcTxn.BigfileOutputs, types.BigfileOutput{
			Address: addr,
			Value:   scChange,
		})
	}

	for _, bige := range bigfiles {
		fcTxn.BigfileInputs = append(fcTxn.BigfileInputs, types.BigfileInput{
			ParentID:         bige.ID,
			UnlockConditions: uc,
		})
		fcTxn.Signatures = append(fcTxn.Signatures, types.TransactionSignature{
			ParentID:      types.Hash256(bige.ID),
			CoveredFields: types.CoveredFields{WholeTransaction: true},
		})
	}

	cs = cm.TipState()
	for i, sig := range fcTxn.Signatures {
		sigHash := cs.WholeSigHash(fcTxn, sig.ParentID, 0, 0, nil)
		sig := pk.SignHash(sigHash)
		fcTxn.Signatures[i].Signature = sig[:]
	}

	if _, err := cm.AddPoolTransactions([]types.Transaction{fcTxn}); err != nil {
		t.Fatal(err)
	}

	testutil.MineBlocks(t, cm, types.VoidAddress, 1)
	waitForBlock(t, cm, db)

	cs = cm.TipState()
	if !cs.BigfundTaxRevenue.Equals(expectedTaxRevenue) {
		t.Fatalf("expected %v tax revenue, got %v", expectedTaxRevenue, cs.BigfundTaxRevenue)
	}

	// claim the bigfunds again. A claim event should be created to account for the
	// tax revenue.
	bigfunds, _, change, err = wm.SelectBigfundElements(w.ID, bigfundValue)
	if err != nil {
		t.Fatal(err)
	} else if change != 0 {
		t.Fatalf("expected no change, got %v", change)
	}
	txn = types.Transaction{
		BigfundOutputs: []types.BigfundOutput{
			{Address: addr, Value: bigfundValue},
		},
	}
	for _, bfe := range bigfunds {
		txn.BigfundInputs = append(txn.BigfundInputs, types.BigfundInput{
			ParentID:         bfe.ID,
			UnlockConditions: uc,
			ClaimAddress:     addr,
		})
		txn.Signatures = append(txn.Signatures, types.TransactionSignature{
			ParentID:      types.Hash256(bfe.ID),
			CoveredFields: types.CoveredFields{WholeTransaction: true},
		})
	}
	cs = cm.TipState()
	for i, sig := range txn.Signatures {
		sigHash := cs.WholeSigHash(txn, sig.ParentID, 0, 0, nil)
		sig := pk.SignHash(sigHash)
		txn.Signatures[i].Signature = sig[:]
	}
	if _, err := cm.AddPoolTransactions([]types.Transaction{txn}); err != nil {
		t.Fatal(err)
	}
	testutil.MineBlocks(t, cm, types.VoidAddress, 1)
	waitForBlock(t, cm, db)

	events, err = wm.WalletEvents(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 10 { // airdrop + 2x bigfund transaction + 5x miner payouts + 1x file contract + 1x bigfund claim
		t.Fatalf("expected 10 events, got %v", len(events))
	}

	// check the bigfund claim event
	expectedID := txn.BigfundInputs[0].ParentID.ClaimOutputID()
	claimEvent := events[0]
	switch {
	case claimEvent.ID != types.Hash256(expectedID):
		t.Fatalf("expected bigfund claim output %q, got %q", expectedID, claimEvent.ID)
	case claimEvent.Type != wallet.EventTypeBigfundClaim:
		t.Fatalf("expected bigfund claim event, got %v", claimEvent.Type)
	case !claimEvent.BigfileInflow().Equals(expectedTaxRevenue):
		t.Fatalf("expected %v tax revenue, got %v", expectedTaxRevenue, claimEvent.BigfileInflow())
	case !claimEvent.BigfileOutflow().IsZero():
		t.Fatalf("expected no outflow, got %v", claimEvent.BigfileOutflow())
	}

	// mine until the bigfund claim output is mature
	testutil.MineBlocks(t, cm, types.VoidAddress, int(network.MaturityDelay))
	waitForBlock(t, cm, db)

	// check that the output is now spendable
	bigfiles, _, err = wm.UnspentBigfileOutputs(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, bige := range bigfiles {
		if bige.ID == expectedID && bige.BigfileOutput.Value.Equals(expectedTaxRevenue) {
			return
		}
	}
	t.Fatalf("expected bigfund claim output %q with value %v not found", expectedID, expectedTaxRevenue)
}

func TestV2BigfundClaims(t *testing.T) {
	pk := types.GeneratePrivateKey()
	addr := types.StandardAddress(pk.PublicKey())

	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	network, genesis := testutil.V2Network()
	// send the bigfunds to the owned address
	genesis.Transactions[0].BigfundOutputs[0].Address = addr
	bigfundValue := genesis.Transactions[0].BigfundOutputs[0].Value

	store, genesisState, err := chain.NewDBStore(bdb, network, genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	cm := chain.NewManager(store, genesisState)

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	// activate the v2 hardfork
	testutil.MineBlocks(t, cm, types.VoidAddress, 2)

	w, err := wm.AddWallet(wallet.Wallet{Name: "test"})
	if err != nil {
		t.Fatal(err)
	}

	sp := types.SpendPolicy{
		Type: types.PolicyTypePublicKey(pk.PublicKey()),
	}
	err = wm.AddAddresses(w.ID, wallet.Address{
		Address:     addr,
		SpendPolicy: &sp,
	})
	if err != nil {
		t.Fatal(err)
	}

	// rescan to index the genesis block
	if err := wm.Scan(context.Background(), types.ChainIndex{}); err != nil {
		t.Fatal(err)
	}

	// claim the bigfunds. Since tax revenue is 0, no claim event or utxo should be indexed.
	bigfunds, basis, change, err := wm.SelectBigfundElements(w.ID, bigfundValue)
	if err != nil {
		t.Fatal(err)
	} else if change != 0 {
		t.Fatalf("expected no change, got %v", change)
	}
	txn := types.V2Transaction{
		BigfundOutputs: []types.BigfundOutput{
			{Address: addr, Value: bigfundValue},
		},
	}
	for _, bfe := range bigfunds {
		txn.BigfundInputs = append(txn.BigfundInputs, types.V2BigfundInput{
			Parent: bfe.BigfundElement,
			SatisfiedPolicy: types.SatisfiedPolicy{
				Policy: sp,
			},
			ClaimAddress: addr,
		})
	}
	cs := cm.TipState()
	sigHash := cs.InputSigHash(txn)
	for i := range txn.BigfundInputs {
		txn.BigfundInputs[i].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(sigHash)}
	}
	if _, err := cm.AddV2PoolTransactions(basis, []types.V2Transaction{txn}); err != nil {
		t.Fatal(err)
	}
	testutil.MineBlocks(t, cm, types.VoidAddress, 1)
	waitForBlock(t, cm, db)

	bigfiles, _, err := wm.UnspentBigfileOutputs(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(bigfiles) != 0 {
		t.Fatalf("expected no bigfile outputs, got %v", bigfiles)
	}

	events, err := wm.WalletEvents(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 2 { // airdrop + bigfund transaction
		t.Fatalf("expected 2 events, got %v", len(events))
	}

	// fund the wallet with some bigfiles
	testutil.MineBlocks(t, cm, addr, 5)
	testutil.MineBlocks(t, cm, types.VoidAddress, int(network.MaturityDelay))
	waitForBlock(t, cm, db)

	payout := types.Bigfiles(100000)
	cs = cm.TipState()
	fc := types.V2FileContract{
		RenterOutput: types.BigfileOutput{
			Address: types.VoidAddress,
			Value:   payout,
		},
		ProofHeight:      cs.Index.Height + 10,
		ExpirationHeight: cs.Index.Height + 20,
		RenterPublicKey:  pk.PublicKey(),
		HostPublicKey:    pk.PublicKey(),
	}
	sigHash = cs.ContractSigHash(fc)
	fc.RenterSignature = pk.SignHash(sigHash)
	fc.HostSignature = pk.SignHash(sigHash)

	expectedTax := cs.V2FileContractTax(fc)
	fundAmount := payout.Add(expectedTax)

	fcTxn := types.V2Transaction{
		FileContracts: []types.V2FileContract{fc},
	}

	bigfiles, basis, scChange, err := wm.SelectBigfileElements(w.ID, fundAmount, false)
	if err != nil {
		t.Fatal(err)
	}

	if !scChange.IsZero() {
		fcTxn.BigfileOutputs = append(fcTxn.BigfileOutputs, types.BigfileOutput{
			Address: addr,
			Value:   scChange,
		})
	}

	for _, bige := range bigfiles {
		fcTxn.BigfileInputs = append(fcTxn.BigfileInputs, types.V2BigfileInput{
			Parent: bige.BigfileElement,
			SatisfiedPolicy: types.SatisfiedPolicy{
				Policy: sp,
			},
		})
	}

	sigHash = cs.InputSigHash(fcTxn)
	for i := range fcTxn.BigfileInputs {
		fcTxn.BigfileInputs[i].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(sigHash)}
	}

	if _, err := cm.AddV2PoolTransactions(basis, []types.V2Transaction{fcTxn}); err != nil {
		t.Fatal(err)
	}

	testutil.MineBlocks(t, cm, types.VoidAddress, 1)
	waitForBlock(t, cm, db)

	cs = cm.TipState()
	if !cs.BigfundTaxRevenue.Equals(expectedTax) {
		t.Fatalf("expected %v tax revenue, got %v", expectedTax, cs.BigfundTaxRevenue)
	}

	// claim the bigfunds again. A claim event should be created to account for the
	// tax revenue.
	bigfunds, basis, change, err = wm.SelectBigfundElements(w.ID, bigfundValue)
	if err != nil {
		t.Fatal(err)
	} else if change != 0 {
		t.Fatalf("expected no change, got %v", change)
	}
	txn = types.V2Transaction{
		BigfundOutputs: []types.BigfundOutput{
			{Address: addr, Value: bigfundValue},
		},
	}
	for _, bfe := range bigfunds {
		txn.BigfundInputs = append(txn.BigfundInputs, types.V2BigfundInput{
			Parent:          bfe.BigfundElement,
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: sp},
			ClaimAddress:    addr,
		})
	}

	cs = cm.TipState()
	sigHash = cs.InputSigHash(txn)
	for i := range txn.BigfundInputs {
		txn.BigfundInputs[i].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(sigHash)}
	}
	if _, err := cm.AddV2PoolTransactions(basis, []types.V2Transaction{txn}); err != nil {
		t.Fatal(err)
	}
	testutil.MineBlocks(t, cm, types.VoidAddress, 1)
	waitForBlock(t, cm, db)

	events, err = wm.WalletEvents(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 10 { // airdrop + 2x bigfund transaction + 5x miner payouts + 1x file contract + 1x bigfund claim
		t.Fatalf("expected 10 events, got %v", len(events))
	}

	// check the bigfund claim event
	expectedID := txn.BigfundInputs[0].Parent.ID.V2ClaimOutputID()
	claimEvent := events[0]
	switch {
	case claimEvent.ID != types.Hash256(expectedID):
		t.Fatalf("expected bigfund claim output %q, got %q", expectedID, claimEvent.ID)
	case claimEvent.Type != wallet.EventTypeBigfundClaim:
		t.Fatalf("expected bigfund claim event, got %v", claimEvent.Type)
	case !claimEvent.BigfileInflow().Equals(expectedTax):
		t.Fatalf("expected %v tax revenue, got %v", expectedTax, claimEvent.BigfileInflow())
	case !claimEvent.BigfileOutflow().IsZero():
		t.Fatalf("expected no outflow, got %v", claimEvent.BigfileOutflow())
	}

	// mine until the bigfund claim output is mature
	testutil.MineBlocks(t, cm, types.VoidAddress, int(network.MaturityDelay))
	waitForBlock(t, cm, db)

	// check that the output is now spendable
	bigfiles, _, err = wm.UnspentBigfileOutputs(w.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, bige := range bigfiles {
		if bige.ID == expectedID && bige.BigfileOutput.Value.Equals(expectedTax) {
			return
		}
	}
	t.Fatalf("expected bigfund claim output %q with value %v not found", expectedID, expectedTax)
}

func TestReset(t *testing.T) {
	log := zaptest.NewLogger(t)

	pk := types.GeneratePrivateKey()
	addr := types.StandardUnlockHash(pk.PublicKey())

	network, genesisBlock := testutil.Network()
	// send the bigfunds to the owned address
	genesisBlock.Transactions[0].BigfundOutputs[0].Address = addr

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(t.TempDir(), "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}
	cm1 := chain.NewManager(store, genesisState)

	bdb2, err := coreutils.OpenBoltChainDB(filepath.Join(t.TempDir(), "consensus2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb2.Close()
	store2, genesisState2, err := chain.NewDBStore(bdb2, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}
	cm2 := chain.NewManager(store2, genesisState2)

	// mine blocks before starting the wallet manager
	for i := 0; i < 25; i++ {
		// blocks on the first chain manager go to the void
		b1, ok := coreutils.MineBlock(cm1, types.VoidAddress, 15*time.Second)
		if !ok {
			t.Fatal("failed to mine block")
		} else if err := cm1.AddBlocks([]types.Block{b1}); err != nil {
			t.Fatal(err)
		}

		// blocks on the second one go to the primary address
		b2, ok := coreutils.MineBlock(cm2, addr, 15*time.Second)
		if !ok {
			t.Fatal("failed to mine block")
		} else if err := cm2.AddBlocks([]types.Block{b2}); err != nil {
			t.Fatal(err)
		}
	}

	db, err := sqlite.OpenDatabase(filepath.Join(t.TempDir(), "walletd.sqlite3"), sqlite.WithLog(log.Named("sqlite3")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// wait for the manager to sync to the first chain
	wm, err := wallet.NewManager(cm1, db, wallet.WithLogger(log.Named("wallet")), wallet.WithIndexMode(wallet.IndexModeFull))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	waitForBlock(t, cm1, db)

	assertBalance := func(t *testing.T, addr types.Address, bigfile, immature types.Currency, bigfund uint64) {
		t.Helper()

		balance, err := db.AddressBalance(addr)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case !balance.Bigfiles.Equals(bigfile):
			t.Fatalf("expected %v BIG, got %v", bigfile, balance.Bigfiles)
		case !balance.ImmatureBigfiles.Equals(immature):
			t.Fatalf("expected immature %v BIG, got %v", bigfile, balance.Bigfiles)
		case balance.Bigfunds != bigfund:
			t.Fatalf("expected %v bigfunds, got %v", bigfund, balance.Bigfunds)
		}
	}

	assertBalance(t, addr, types.ZeroCurrency, types.ZeroCurrency, 10000)

	// close the manager
	if err := wm.Close(); err != nil {
		t.Fatal()
	}

	// calculate the expected balances
	_, applied, err := cm2.UpdatesSince(types.ChainIndex{}, 1000)
	if err != nil {
		t.Fatal(err)
	}

	var bigfileElements []types.BigfileElement
	for _, cau := range applied {
		for _, biged := range cau.BigfileElementDiffs() {
			if biged.Created && biged.BigfileElement.BigfileOutput.Address == addr {
				bigfileElements = append(bigfileElements, biged.BigfileElement)
			}
		}
	}

	var expectedBigfiles, expectedImmature types.Currency
	for _, bige := range bigfileElements {
		if bige.MaturityHeight > cm2.Tip().Height {
			expectedImmature = expectedImmature.Add(bige.BigfileOutput.Value)
		} else {
			expectedBigfiles = expectedBigfiles.Add(bige.BigfileOutput.Value)
		}
	}

	wm, err = wallet.NewManager(cm2, db, wallet.WithLogger(log.Named("wallet")), wallet.WithIndexMode(wallet.IndexModeFull))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	waitForBlock(t, cm2, db)

	assertBalance(t, addr, expectedBigfiles, expectedImmature, genesisState.BigfundCount())
}
