package wallet

import (
	"fmt"

	"go.thebigfile.com/core/types"
	"go.thebigfile.com/coreutils/chain"
	"go.uber.org/zap"
)

type (
	// A stateTreeUpdater is an interface for applying and reverting
	// Merkle tree updates.
	stateTreeUpdater interface {
		UpdateElementProof(*types.StateElement)
		ForEachTreeNode(fn func(row uint64, col uint64, h types.Hash256))
	}

	// A ProofUpdater is an interface for updating Merkle proofs.
	ProofUpdater interface {
		UpdateElementProof(*types.StateElement)
	}

	// AddressBalance pairs an address with its balance.
	AddressBalance struct {
		Address types.Address `json:"address"`
		Balance
	}

	// SpentBigfileElement pairs a spent bigfile element with the ID of the
	// transaction that spent it.
	SpentBigfileElement struct {
		types.BigfileElement
		EventID types.TransactionID
	}

	// SpentBigfundElement pairs a spent bigfund element with the ID of the
	// transaction that spent it.
	SpentBigfundElement struct {
		types.BigfundElement
		EventID types.TransactionID
	}

	// AppliedState contains all state changes made to a store after applying a chain
	// update.
	AppliedState struct {
		NumLeaves              uint64
		Events                 []Event
		CreatedBigfileElements []types.BigfileElement
		SpentBigfileElements   []SpentBigfileElement
		CreatedBigfundElements []types.BigfundElement
		SpentBigfundElements   []SpentBigfundElement
	}

	// RevertedState contains all state changes made to a store after reverting
	// a chain update.
	RevertedState struct {
		NumLeaves              uint64
		UnspentBigfileElements []types.BigfileElement
		DeletedBigfileElements []types.BigfileElement
		UnspentBigfundElements []types.BigfundElement
		DeletedBigfundElements []types.BigfundElement
	}

	// A TreeNodeUpdate contains the hash of a Merkle tree node and its row and
	// column indices.
	TreeNodeUpdate struct {
		Hash   types.Hash256
		Row    int
		Column int
	}

	// An UpdateTx atomically updates the state of a store.
	UpdateTx interface {
		UpdateStateElementProofs(ProofUpdater) error
		UpdateStateTree([]TreeNodeUpdate) error

		AddressRelevant(types.Address) (bool, error)

		ApplyIndex(types.ChainIndex, AppliedState) error
		RevertIndex(types.ChainIndex, RevertedState) error
	}
)

// updateStateElements updates the state elements in a store according to the
// changes made by a chain update.
func updateStateElements(tx UpdateTx, update stateTreeUpdater, indexMode IndexMode) error {
	if indexMode == IndexModeNone {
		panic("updateStateElements called with IndexModeNone") // developer error
	}

	if indexMode == IndexModeFull {
		var updates []TreeNodeUpdate
		update.ForEachTreeNode(func(row, col uint64, h types.Hash256) {
			updates = append(updates, TreeNodeUpdate{h, int(row), int(col)})
		})
		return tx.UpdateStateTree(updates)
	} else {
		return tx.UpdateStateElementProofs(update)
	}
}

// applyChainUpdate atomically applies a chain update to a store
func applyChainUpdate(tx UpdateTx, cau chain.ApplyUpdate, indexMode IndexMode) error {
	applied := AppliedState{
		NumLeaves: cau.State.Elements.NumLeaves,
	}

	spentEventIDs := make(map[types.Hash256]types.TransactionID)
	for _, txn := range cau.Block.Transactions {
		txnID := txn.ID()
		for _, input := range txn.BigfileInputs {
			spentEventIDs[types.Hash256(input.ParentID)] = txnID
		}
		for _, input := range txn.BigfundInputs {
			spentEventIDs[types.Hash256(input.ParentID)] = txnID
		}
	}
	for _, txn := range cau.Block.V2Transactions() {
		txnID := txn.ID()
		for _, input := range txn.BigfileInputs {
			spentEventIDs[types.Hash256(input.Parent.ID)] = txnID
		}
		for _, input := range txn.BigfundInputs {
			spentEventIDs[types.Hash256(input.Parent.ID)] = txnID
		}
	}

	// add new bigfile elements to the store
	for _, biged := range cau.BigfileElementDiffs() {
		bige := biged.BigfileElement
		if (biged.Created && biged.Spent) || bige.BigfileOutput.Value.IsZero() {
			continue
		} else if relevant, err := tx.AddressRelevant(bige.BigfileOutput.Address); err != nil {
			panic(err)
		} else if !relevant {
			continue
		}
		if biged.Spent {
			spentTxnID, ok := spentEventIDs[types.Hash256(bige.ID)]
			if !ok {
				panic(fmt.Errorf("missing transaction ID for spent bigfile element %v", bige.ID))
			}
			applied.SpentBigfileElements = append(applied.SpentBigfileElements, SpentBigfileElement{
				BigfileElement: bige,
				EventID:        spentTxnID,
			})
		} else {
			applied.CreatedBigfileElements = append(applied.CreatedBigfileElements, bige)
		}
	}
	for _, sfed := range cau.BigfundElementDiffs() {
		bfe := sfed.BigfundElement
		if (sfed.Created && sfed.Spent) || bfe.BigfundOutput.Value == 0 {
			continue
		} else if relevant, err := tx.AddressRelevant(bfe.BigfundOutput.Address); err != nil {
			panic(err)
		} else if !relevant {
			continue
		}
		if sfed.Spent {
			spentTxnID, ok := spentEventIDs[types.Hash256(bfe.ID)]
			if !ok {
				panic(fmt.Errorf("missing transaction ID for spent bigfund element %v", bfe.ID))
			}
			applied.SpentBigfundElements = append(applied.SpentBigfundElements, SpentBigfundElement{
				BigfundElement: bfe,
				EventID:        spentTxnID,
			})
		} else {
			applied.CreatedBigfundElements = append(applied.CreatedBigfundElements, bfe)
		}
	}

	// add events
	relevant := func(addr types.Address) bool {
		relevant, err := tx.AddressRelevant(addr)
		if err != nil {
			panic(fmt.Errorf("failed to check if address is relevant: %w", err))
		}
		return relevant
	}
	applied.Events = AppliedEvents(cau.State, cau.Block, cau, relevant)

	if err := updateStateElements(tx, cau, indexMode); err != nil {
		return fmt.Errorf("failed to update state elements: %w", err)
	} else if err := tx.ApplyIndex(cau.State.Index, applied); err != nil {
		return fmt.Errorf("failed to apply index: %w", err)
	}
	return nil
}

// revertChainUpdate atomically reverts a chain update from a store
func revertChainUpdate(tx UpdateTx, cru chain.RevertUpdate, revertedIndex types.ChainIndex, indexMode IndexMode) error {
	reverted := RevertedState{
		NumLeaves: cru.State.Elements.NumLeaves,
	}

	// determine which bigfile and bigfund elements are ephemeral
	//
	// note: I thought we could use LeafIndex == EphemeralLeafIndex, but
	// it seems to be set before the subscriber is called.
	created := make(map[types.Hash256]bool)
	ephemeral := make(map[types.Hash256]bool)
	for _, txn := range cru.Block.Transactions {
		for i := range txn.BigfileOutputs {
			created[types.Hash256(txn.BigfileOutputID(i))] = true
		}
		for _, input := range txn.BigfileInputs {
			ephemeral[types.Hash256(input.ParentID)] = created[types.Hash256(input.ParentID)]
		}
		for i := range txn.BigfundOutputs {
			created[types.Hash256(txn.BigfundOutputID(i))] = true
		}
		for _, input := range txn.BigfundInputs {
			ephemeral[types.Hash256(input.ParentID)] = created[types.Hash256(input.ParentID)]
		}
	}

	for _, biged := range cru.BigfileElementDiffs() {
		bige := biged.BigfileElement
		if (biged.Created && biged.Spent) || bige.BigfileOutput.Value.IsZero() {
			continue
		} else if relevant, err := tx.AddressRelevant(bige.BigfileOutput.Address); err != nil {
			panic(err)
		} else if !relevant {
			continue
		}
		if biged.Spent {
			// re-add any spent bigfile elements
			reverted.UnspentBigfileElements = append(reverted.UnspentBigfileElements, bige)
		} else {
			// delete any created bigfile elements
			reverted.DeletedBigfileElements = append(reverted.DeletedBigfileElements, bige)
		}
	}
	for _, sfed := range cru.BigfundElementDiffs() {
		bfe := sfed.BigfundElement
		if (sfed.Created && sfed.Spent) || bfe.BigfundOutput.Value == 0 {
			continue
		} else if relevant, err := tx.AddressRelevant(bfe.BigfundOutput.Address); err != nil {
			panic(err)
		} else if !relevant {
			continue
		}
		if sfed.Spent {
			reverted.UnspentBigfundElements = append(reverted.UnspentBigfundElements, bfe)
		} else {
			reverted.DeletedBigfundElements = append(reverted.DeletedBigfundElements, bfe)
		}
	}

	if err := tx.RevertIndex(revertedIndex, reverted); err != nil {
		return fmt.Errorf("failed to revert index: %w", err)
	}
	return updateStateElements(tx, cru, indexMode)
}

// UpdateChainState atomically updates the state of a store with a set of
// updates from the chain manager.
func UpdateChainState(tx UpdateTx, reverted []chain.RevertUpdate, applied []chain.ApplyUpdate, indexMode IndexMode, log *zap.Logger) error {
	for _, cru := range reverted {
		revertedIndex := types.ChainIndex{
			ID:     cru.Block.ID(),
			Height: cru.State.Index.Height + 1,
		}
		if err := revertChainUpdate(tx, cru, revertedIndex, indexMode); err != nil {
			return fmt.Errorf("failed to revert chain update %q: %w", revertedIndex, err)
		}
		log.Debug("reverted chain update", zap.Stringer("blockID", revertedIndex.ID), zap.Uint64("height", revertedIndex.Height))
	}

	for _, cau := range applied {
		// apply the chain update
		if err := applyChainUpdate(tx, cau, indexMode); err != nil {
			return fmt.Errorf("failed to apply chain update %q: %w", cau.State.Index, err)
		}
		log.Debug("applied chain update", zap.Stringer("blockID", cau.State.Index.ID), zap.Uint64("height", cau.State.Index.Height))
	}
	return nil
}
