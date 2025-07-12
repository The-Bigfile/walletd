package wallet_test

import (
	"testing"

	"go.thebigfile.com/core/types"
	"go.thebigfile.com/walletd/v2/internal/testutil"
	"go.thebigfile.com/walletd/v2/wallet"
	"go.uber.org/zap/zaptest"
	"lukechampine.com/frand"
)

func TestAddressUseTpool(t *testing.T) {
	log := zaptest.NewLogger(t)

	// mine a single payout to the wallet
	pk := types.GeneratePrivateKey()
	uc := types.StandardUnlockConditions(pk.PublicKey())
	addr1 := uc.UnlockHash()

	network, genesisBlock := testutil.V2Network()
	genesisBlock.Transactions[0].BigfileOutputs = []types.BigfileOutput{
		{Address: addr1, Value: types.Bigfiles(100)},
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

	assertBigfileElement := func(t *testing.T, id types.BigfileOutputID, value types.Currency, confirmations uint64) {
		t.Helper()

		utxos, _, err := wm.AddressBigfileOutputs(addr1, true, 0, 1)
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

	airdropID := genesisBlock.Transactions[0].BigfileOutputID(0)
	assertBigfileElement(t, airdropID, types.Bigfiles(100), 2)

	utxos, basis, err := wm.AddressBigfileOutputs(addr1, true, 0, 100)
	if err != nil {
		t.Fatal(err)
	}

	cs := cm.TipState()
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

	if _, err := cm.AddV2PoolTransactions(basis, []types.V2Transaction{txn}); err != nil {
		t.Fatal(err)
	}
	wm.SyncPool() // force reindexing of the tpool
	assertBigfileElement(t, txn.BigfileOutputID(txn.ID(), 1), types.Bigfiles(75), 0)
	cn.MineBlocks(t, types.VoidAddress, 1)
	assertBigfileElement(t, txn.BigfileOutputID(txn.ID(), 1), types.Bigfiles(75), 1)
}

func TestBatchAddresses(t *testing.T) {
	log := zaptest.NewLogger(t)

	network, genesisBlock := testutil.V2Network()
	cn := testutil.NewConsensusNode(t, network, genesisBlock, log)
	cm := cn.Chain
	db := cn.Store

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")), wallet.WithIndexMode(wallet.IndexModeFull))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	// mine a bunch of payouts to different addresses
	addresses := make([]types.Address, 100)
	for i := range addresses {
		addresses[i] = types.StandardAddress(types.GeneratePrivateKey().PublicKey())
		cn.MineBlocks(t, addresses[i], 1)
	}

	events, err := wm.BatchAddressEvents(addresses, 0, 1000)
	if err != nil {
		t.Fatal(err)
	} else if len(events) != 100 {
		t.Fatalf("expected 100 events, got %d", len(events))
	}
}

func TestBatchBigfileOutputs(t *testing.T) {
	log := zaptest.NewLogger(t)

	network, genesisBlock := testutil.V2Network()
	cn := testutil.NewConsensusNode(t, network, genesisBlock, log)
	cm := cn.Chain
	db := cn.Store

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")), wallet.WithIndexMode(wallet.IndexModeFull))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	// mine a bunch of payouts to different addresses
	addresses := make([]types.Address, 100)
	for i := range addresses {
		addresses[i] = types.StandardAddress(types.GeneratePrivateKey().PublicKey())
		cn.MineBlocks(t, addresses[i], 1)
	}
	cn.MineBlocks(t, types.VoidAddress, int(network.MaturityDelay))

	biges, _, err := wm.BatchAddressBigfileOutputs(addresses, 0, 1000)
	if err != nil {
		t.Fatal(err)
	} else if len(biges) != 100 {
		t.Fatalf("expected 100 events, got %d", len(biges))
	}
}

func TestBatchBigfundOutputs(t *testing.T) {
	log := zaptest.NewLogger(t)

	giftAddr := types.AnyoneCanSpend().Address()
	network, genesisBlock := testutil.V2Network()
	genesisBlock.Transactions[0].BigfundOutputs = []types.BigfundOutput{
		{Address: giftAddr, Value: 10000},
	}
	cn := testutil.NewConsensusNode(t, network, genesisBlock, log)
	cm := cn.Chain
	db := cn.Store

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")), wallet.WithIndexMode(wallet.IndexModeFull))
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()

	cn.WaitForSync(t)

	// distribute the bigfund output to multiple addresses
	var addresses []types.Address
	outputID := genesisBlock.Transactions[0].BigfundOutputID(0)
	outputValue := genesisBlock.Transactions[0].BigfundOutputs[0].Value
	for i := range 100 {
		txn := types.V2Transaction{
			BigfundInputs: []types.V2BigfundInput{
				{
					Parent: types.BigfundElement{
						ID: outputID,
					},
					SatisfiedPolicy: types.SatisfiedPolicy{
						Policy: types.AnyoneCanSpend(),
					},
				},
			},
		}

		for range 10 {
			address := types.StandardAddress(types.GeneratePrivateKey().PublicKey())
			addresses = append(addresses, address)
			txn.BigfundOutputs = append(txn.BigfundOutputs, types.BigfundOutput{
				Address: address,
				Value:   1,
			})
			outputValue--
			if outputValue == 0 {
				break
			}
		}

		if outputValue > 0 {
			txn.BigfundOutputs = append(txn.BigfundOutputs, types.BigfundOutput{
				Address: giftAddr,
				Value:   outputValue,
			})
		}
		outputID = txn.BigfundOutputID(txn.ID(), len(txn.BigfundOutputs)-1)
		basis, txns, err := db.OverwriteElementProofs([]types.V2Transaction{txn})
		if err != nil {
			t.Fatalf("failed to update element proofs %d: %s", i, err)
		}
		if _, err := cm.AddV2PoolTransactions(basis, txns); err != nil {
			t.Fatalf("failed to add pool transactions %d: %s", i, err)
		}
		cn.MineBlocks(t, types.VoidAddress, 1)
	}

	bfes, _, err := wm.BatchAddressBigfundOutputs(addresses, 0, 10000)
	if err != nil {
		t.Fatal(err)
	} else if len(bfes) != 1000 {
		t.Fatalf("expected 1000 events, got %d", len(bfes))
	}
}

func BenchmarkBatchAddresses(b *testing.B) {
	log := zaptest.NewLogger(b)

	network, genesisBlock := testutil.V2Network()
	cn := testutil.NewConsensusNode(b, network, genesisBlock, log)
	cm := cn.Chain
	db := cn.Store

	wm, err := wallet.NewManager(cm, db, wallet.WithLogger(log.Named("wallet")), wallet.WithIndexMode(wallet.IndexModeFull))
	if err != nil {
		b.Fatal(err)
	}
	defer wm.Close()

	// mine a bunch of payouts to different addresses
	addresses := make([]types.Address, 10000)
	for i := range addresses {
		addresses[i] = types.StandardAddress(types.GeneratePrivateKey().PublicKey())
		cn.MineBlocks(b, addresses[i], 1)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		slice := addresses[frand.Intn(len(addresses)-1000):][:1000]
		events, err := wm.BatchAddressEvents(slice, 0, 100)
		if err != nil {
			b.Fatal(err)
		} else if len(events) != 100 {
			b.Fatalf("expected 100 events, got %d", len(events))
		}
	}
}
