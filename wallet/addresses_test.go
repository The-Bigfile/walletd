package wallet_test

import (
	"testing"

	"go.thebigfile.com/core/types"
	"go.thebigfile.com/walletd/v2/internal/testutil"
	"go.thebigfile.com/walletd/v2/wallet"
	"go.uber.org/zap/zaptest"
)

func TestAddressUseTpool(t *testing.T) {
	log := zaptest.NewLogger(t)

	// mine a single payout to the wallet
	pk := types.GeneratePrivateKey()
	uc := types.StandardUnlockConditions(pk.PublicKey())
	addr1 := uc.UnlockHash()

	network, genesisBlock := testutil.V2Network()
	genesisBlock.Transactions[0].BigFileOutputs = []types.BigFileOutput{
		{Address: addr1, Value: types.BigFiles(100)},
	}
	cn := testutil.NewConsensusNode(t, network, genesisBlock, log)
	cm := cn.Chain
	db := cn.Store

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")), wallet.WithIndexMode(wallet.IndexModeFull))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	cn.MineBlocks(t, types.VoidAddress, 1)

	assertBigFileElement := func(t *testing.T, id types.BigFileOutputID, value types.Currency, confirmations uint64) {
		t.Helper()

		utxos, _, err := wm.AddressBigFileOutputs(addr1, true, 0, 1)
		if err != nil {
			t.Fatal(err)
		}
		for _, sce := range utxos {
			if sce.ID == id {
				if !sce.BigFileOutput.Value.Equals(value) {
					t.Fatalf("expected value %v, got %v", value, sce.BigFileOutput.Value)
				} else if sce.Confirmations != confirmations {
					t.Fatalf("expected confirmations %d, got %d", confirmations, sce.Confirmations)
				}
				return
			}
		}
		t.Fatalf("expected bigfile element with ID %q not found", id)
	}

	airdropID := genesisBlock.Transactions[0].BigFileOutputID(0)
	assertBigFileElement(t, airdropID, types.BigFiles(100), 2)

	utxos, basis, err := wm.AddressBigFileOutputs(addr1, true, 0, 100)
	if err != nil {
		t.Fatal(err)
	}

	cs := cm.TipState()
	txn := types.V2Transaction{
		BigFileInputs: []types.V2BigFileInput{
			{
				Parent: utxos[0].BigFileElement,
				SatisfiedPolicy: types.SatisfiedPolicy{
					Policy: types.SpendPolicy{
						Type: types.PolicyTypeUnlockConditions(uc),
					},
				},
			},
		},
		BigFileOutputs: []types.BigFileOutput{
			{
				Address: types.VoidAddress,
				Value:   types.BigFiles(25),
			},
			{
				Address: addr1,
				Value:   types.BigFiles(75),
			},
		},
	}
	sigHash := cs.InputSigHash(txn)
	txn.BigFileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{
		pk.SignHash(sigHash),
	}

	if _, err := cm.AddV2PoolTransactions(basis, []types.V2Transaction{txn}); err != nil {
		t.Fatal(err)
	}
	wm.SyncPool() // force reindexing of the tpool
	assertBigFileElement(t, txn.BigFileOutputID(txn.ID(), 1), types.BigFiles(75), 0)
	cn.MineBlocks(t, types.VoidAddress, 1)
	assertBigFileElement(t, txn.BigFileOutputID(txn.ID(), 1), types.BigFiles(75), 1)
}
