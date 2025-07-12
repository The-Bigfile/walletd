package sqlite

import (
	"path/filepath"
	"testing"

	"go.thebigfile.com/core/consensus"
	"go.thebigfile.com/core/types"
	"go.thebigfile.com/coreutils"
	"go.thebigfile.com/coreutils/chain"
	"go.thebigfile.com/coreutils/testutil"
	"go.thebigfile.com/walletd/v2/wallet"
	"go.uber.org/zap/zaptest"
)

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

func syncDB(tb testing.TB, store *Store, cm *chain.Manager) {
	index, err := store.LastCommittedIndex()
	if err != nil {
		tb.Fatalf("failed to get last committed index: %v", err)
	}
	for index != cm.Tip() {
		crus, caus, err := cm.UpdatesSince(index, 1000)
		if err != nil {
			tb.Fatalf("failed to subscribe to chain manager: %v", err)
		} else if err := store.UpdateChainState(crus, caus); err != nil {
			tb.Fatalf("failed to update chain state: %v", err)
		}

		switch {
		case len(caus) > 0:
			index = caus[len(caus)-1].State.Index
		case len(crus) > 0:
			index = crus[len(crus)-1].State.Index
		}
	}
}

func TestPruneBigfiles(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), WithLog(log.Named("sqlite3")), WithRetainSpentElements(20))
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
	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	// create a wallet
	w, err := db.AddWallet(wallet.Wallet{Name: "test"})
	if err != nil {
		t.Fatal(err)
	} else if err := db.AddWalletAddresses(w.ID, wallet.Address{Address: addr}); err != nil {
		t.Fatal(err)
	}

	// mine a block to the wallet
	expectedPayout := cm.TipState().BlockReward()
	maturityHeight := cm.TipState().MaturityHeight()
	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, addr)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	assertBalance := func(bigfile, immature types.Currency) {
		t.Helper()

		b, err := db.WalletBalance(w.ID)
		if err != nil {
			t.Fatalf("failed to get wallet balance: %v", err)
		} else if !b.ImmatureBigfiles.Equals(immature) {
			t.Fatalf("expected immature bigfile balance %v, got %v", immature, b.ImmatureBigfiles)
		} else if !b.Bigfiles.Equals(bigfile) {
			t.Fatalf("expected bigfile balance %v, got %v", bigfile, b.Bigfiles)
		}
	}

	assertUTXOs := func(spent int, unspent int) {
		t.Helper()

		var n int
		err := db.db.QueryRow(`SELECT COUNT(*) FROM bigfile_elements WHERE spent_index_id IS NOT NULL`).Scan(&n)
		if err != nil {
			t.Fatalf("failed to count spent bigfile elements: %v", err)
		} else if n != spent {
			t.Fatalf("expected %v spent bigfile elements, got %v", spent, n)
		}

		err = db.db.QueryRow(`SELECT COUNT(*) FROM bigfile_elements WHERE spent_index_id IS NULL`).Scan(&n)
		if err != nil {
			t.Fatalf("failed to count unspent bigfile elements: %v", err)
		} else if n != unspent {
			t.Fatalf("expected %v unspent bigfile elements, got %v", unspent, n)
		}
	}

	assertBalance(types.ZeroCurrency, expectedPayout)
	assertUTXOs(0, 1)

	// mine until the payout matures
	for range maturityHeight {
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
	}
	syncDB(t, db, cm)
	assertBalance(expectedPayout, types.ZeroCurrency)
	assertUTXOs(0, 1)

	// spend the utxo
	utxos, _, err := db.WalletBigfileOutputs(w.ID, 0, 100)
	if err != nil {
		t.Fatalf("failed to get wallet bigfile outputs: %v", err)
	}

	txn := types.Transaction{
		BigfileInputs: []types.BigfileInput{{
			ParentID:         types.BigfileOutputID(utxos[0].ID),
			UnlockConditions: types.StandardUnlockConditions(pk.PublicKey()),
		}},
		BigfileOutputs: []types.BigfileOutput{
			{Value: utxos[0].BigfileOutput.Value, Address: types.VoidAddress},
		},
	}

	sigHash := cm.TipState().WholeSigHash(txn, types.Hash256(utxos[0].ID), 0, 0, nil)
	sig := pk.SignHash(sigHash)
	txn.Signatures = append(txn.Signatures, types.TransactionSignature{
		ParentID:       types.Hash256(utxos[0].ID),
		CoveredFields:  types.CoveredFields{WholeTransaction: true},
		PublicKeyIndex: 0,
		Timelock:       0,
		Signature:      sig[:],
	})

	// mine a block with the transaction
	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), []types.Transaction{txn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	// the utxo should now have 0 balance and 1 spent element
	assertBalance(types.ZeroCurrency, types.ZeroCurrency)
	assertUTXOs(1, 0)

	// mine until the element is pruned
	for i := uint64(0); i < db.spentElementRetentionBlocks-1; i++ {
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)
		assertUTXOs(1, 0) // check that the element is not pruned early
	}

	// trigger the pruning
	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)
	assertUTXOs(0, 0)
}

func TestPruneBigfunds(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := OpenDatabase(filepath.Join(dir, "walletd.sqlite3"), WithLog(log.Named("sqlite3")))
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
	// send the bigfund airdrop to the wallet
	genesisBlock.Transactions[0].BigfundOutputs[0].Address = addr
	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	// create a wallet
	w, err := db.AddWallet(wallet.Wallet{Name: "test"})
	if err != nil {
		t.Fatal(err)
	} else if err := db.AddWalletAddresses(w.ID, wallet.Address{Address: addr}); err != nil {
		t.Fatal(err)
	}

	syncDB(t, db, cm)

	assertBalance := func(bigfunds uint64) {
		t.Helper()

		b, err := db.WalletBalance(w.ID)
		if err != nil {
			t.Fatalf("failed to get wallet balance: %v", err)
		} else if b.Bigfunds != bigfunds {
			t.Fatalf("expected bigfund balance %v, got %v", bigfunds, b.ImmatureBigfiles)
		}
	}

	assertUTXOs := func(spent int, unspent int) {
		t.Helper()

		var n int
		err := db.db.QueryRow(`SELECT COUNT(*) FROM bigfund_elements WHERE spent_index_id IS NOT NULL`).Scan(&n)
		if err != nil {
			t.Fatalf("failed to count spent bigfile elements: %v", err)
		} else if n != spent {
			t.Fatalf("expected %v spent bigfile elements, got %v", spent, n)
		}

		err = db.db.QueryRow(`SELECT COUNT(*) FROM bigfund_elements WHERE spent_index_id IS NULL`).Scan(&n)
		if err != nil {
			t.Fatalf("failed to count unspent bigfile elements: %v", err)
		} else if n != unspent {
			t.Fatalf("expected %v unspent bigfile elements, got %v", unspent, n)
		}
	}

	assertBalance(cm.TipState().BigfundCount())
	assertUTXOs(0, 1)

	// spend the utxo
	utxos, _, err := db.WalletBigfundOutputs(w.ID, 0, 100)
	if err != nil {
		t.Fatalf("failed to get wallet bigfile outputs: %v", err)
	}

	txn := types.Transaction{
		BigfundInputs: []types.BigfundInput{{
			ParentID:         types.BigfundOutputID(utxos[0].ID),
			UnlockConditions: types.StandardUnlockConditions(pk.PublicKey()),
		}},
		BigfundOutputs: []types.BigfundOutput{
			{Value: utxos[0].BigfundOutput.Value, Address: types.VoidAddress},
		},
	}

	sigHash := cm.TipState().WholeSigHash(txn, types.Hash256(utxos[0].ID), 0, 0, nil)
	sig := pk.SignHash(sigHash)
	txn.Signatures = append(txn.Signatures, types.TransactionSignature{
		ParentID:       types.Hash256(utxos[0].ID),
		CoveredFields:  types.CoveredFields{WholeTransaction: true},
		PublicKeyIndex: 0,
		Timelock:       0,
		Signature:      sig[:],
	})

	// mine a block with the transaction
	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), []types.Transaction{txn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	// the utxo should now have 0 balance and 1 spent element
	assertBalance(0)
	assertUTXOs(1, 0)

	// mine until the element is pruned
	for i := uint64(0); i < db.spentElementRetentionBlocks-1; i++ {
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm) // check that the element is not pruned early
		assertUTXOs(1, 0)
	}

	// the spent element should now be pruned
	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)
	assertUTXOs(0, 0)
}
