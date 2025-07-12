package sqlite

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"

	"go.thebigfile.com/core/consensus"
	"go.thebigfile.com/core/types"
	"go.thebigfile.com/coreutils/chain"
	"go.thebigfile.com/walletd/v2/wallet"
	"go.uber.org/zap"
)

type updateTx struct {
	indexMode wallet.IndexMode

	tx                *txn
	relevantAddresses map[types.Address]bool
}

type addressRef struct {
	ID      int64
	Balance wallet.Balance
}

type stateElement struct {
	ID types.Hash256
	types.StateElement
}

func (ut *updateTx) UpdateStateElementProofs(update wallet.ProofUpdater) error {
	if ut.indexMode == wallet.IndexModeFull {
		panic("UpdateStateElementProofs called in full index mode")
	}

	se, err := getBigfileStateElements(ut.tx)
	if err != nil {
		return fmt.Errorf("failed to get bigfile state elements: %w", err)
	}
	for i := range se {
		update.UpdateElementProof(&se[i].StateElement)
	}
	if err := updateBigfileStateElements(ut.tx, se); err != nil {
		return fmt.Errorf("failed to update bigfile state elements: %w", err)
	}

	bfe, err := getBigfundStateElements(ut.tx)
	if err != nil {
		return fmt.Errorf("failed to get bigfund state elements: %w", err)
	}
	for i := range bfe {
		update.UpdateElementProof(&bfe[i].StateElement)
	}
	if err := updateBigfundStateElements(ut.tx, bfe); err != nil {
		return fmt.Errorf("failed to update bigfund state elements: %w", err)
	}
	return nil
}

func (ut *updateTx) UpdateStateTree(changes []wallet.TreeNodeUpdate) error {
	if ut.indexMode != wallet.IndexModeFull {
		panic("UpdateStateTree called in personal index mode")
	}

	stmt, err := ut.tx.Prepare(`INSERT INTO state_tree (row, column, value) VALUES ($1, $2, $3) ON CONFLICT (row, column) DO UPDATE SET value=EXCLUDED.value`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, change := range changes {
		_, err := stmt.Exec(change.Row, change.Column, encode(change.Hash))
		if err != nil {
			return fmt.Errorf("failed to execute statement: %w", err)
		}
	}
	return nil
}

func (ut *updateTx) AddressRelevant(addr types.Address) (bool, error) {
	if ut.indexMode == wallet.IndexModeFull {
		return true, nil
	}

	if relevant, ok := ut.relevantAddresses[addr]; ok {
		return relevant, nil
	}

	var id int64
	err := ut.tx.QueryRow(`SELECT id FROM bigfile_addresses WHERE bigfile_address=$1`, encode(addr)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		ut.relevantAddresses[addr] = false
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("failed to query address: %w", err)
	}
	ut.relevantAddresses[addr] = true
	return ut.relevantAddresses[addr], nil
}

func (ut *updateTx) AddressBalance(addr types.Address) (balance wallet.Balance, err error) {
	err = ut.tx.QueryRow(`SELECT bigfile_balance, immature_bigfile_balance, bigfund_balance FROM bigfile_addresses WHERE bigfile_address=$1`, encode(addr)).Scan(decode(&balance.Bigfiles), decode(&balance.ImmatureBigfiles), &balance.Bigfunds)
	return
}

func (ut *updateTx) ApplyIndex(index types.ChainIndex, state wallet.AppliedState) error {
	tx := ut.tx
	log := tx.log.Named("ApplyIndex").With(zap.Stringer("blockID", index.ID), zap.Uint64("height", index.Height))

	if err := revertOrphans(tx, index, log.Named("revertOrphans")); err != nil {
		return fmt.Errorf("failed to revert orphans: %w", err)
	}

	if err := applyMatureBigfileBalance(tx, index, log.Named("applyMatureBigfileBalance")); err != nil {
		return fmt.Errorf("failed to apply mature bigfile balance: %w", err)
	}

	var indexID int64
	if err := tx.QueryRow(`INSERT INTO chain_indices (block_id, height) VALUES ($1, $2) ON CONFLICT (block_id) DO UPDATE SET height=height RETURNING id`, encode(index.ID), index.Height).Scan(&indexID); err != nil {
		return fmt.Errorf("failed to insert chain index: %w", err)
	}

	if err := addEvents(tx, state.Events, indexID); err != nil {
		return fmt.Errorf("failed to add events: %w", err)
	}

	if err := spendBigfileElements(tx, state.SpentBigfileElements, indexID); err != nil {
		return fmt.Errorf("failed to spend bigfile elements: %w", err)
	} else if err := addBigfileElements(tx, state.CreatedBigfileElements, indexID, ut.indexMode, log.Named("addBigfileElements")); err != nil {
		return fmt.Errorf("failed to add bigfile elements: %w", err)
	}

	if err := spendBigfundElements(tx, state.SpentBigfundElements, indexID); err != nil {
		return fmt.Errorf("failed to spend bigfund elements: %w", err)
	} else if err := addBigfundElements(tx, state.CreatedBigfundElements, indexID, ut.indexMode, log.Named("addBigfundElements")); err != nil {
		return fmt.Errorf("failed to add bigfund elements: %w", err)
	}

	return nil
}

func (ut *updateTx) RevertIndex(index types.ChainIndex, state wallet.RevertedState) error {
	tx := ut.tx

	if err := revertSpentBigfileElements(tx, state.UnspentBigfileElements); err != nil {
		return fmt.Errorf("failed to revert spent bigfile elements: %w", err)
	} else if err := removeBigfileElements(tx, state.DeletedBigfileElements); err != nil {
		return fmt.Errorf("failed to remove bigfile elements: %w", err)
	}

	if err := revertSpentBigfundElements(tx, state.UnspentBigfundElements); err != nil {
		return fmt.Errorf("failed to revert spent bigfund elements: %w", err)
	} else if err := removeBigfundElements(tx, state.DeletedBigfundElements); err != nil {
		return fmt.Errorf("failed to remove bigfund elements: %w", err)
	}

	if err := revertEvents(tx, index); err != nil {
		return fmt.Errorf("failed to revert events: %w", err)
	} else if err := revertMatureBigfileBalance(tx, index); err != nil {
		return fmt.Errorf("failed to revert mature bigfile balance: %w", err)
	}
	return nil
}

// UpdateChainState implements chain.Subscriber
func (s *Store) UpdateChainState(reverted []chain.RevertUpdate, applied []chain.ApplyUpdate) error {
	if len(applied) == 0 && len(reverted) == 0 {
		return nil
	}

	log := s.log.Named("UpdateChainState").With(zap.Int("revertedUpdates", len(reverted)), zap.Int("appliedUpdates", len(applied)))
	return s.transaction(func(tx *txn) error {
		utx := &updateTx{
			indexMode: s.indexMode,

			tx:                tx,
			relevantAddresses: make(map[types.Address]bool),
		}

		if err := wallet.UpdateChainState(utx, reverted, applied, s.indexMode, log); err != nil {
			return err
		}

		var state consensus.State
		switch {
		case len(applied) > 0:
			state = applied[len(applied)-1].State
		case len(reverted) > 0:
			state = reverted[len(reverted)-1].State
		}

		if err := setGlobalState(tx, state.Index, state.Elements.NumLeaves); err != nil {
			return fmt.Errorf("failed to set last committed index: %w", err)
		}

		// skip pruning if there are no applied updates
		if len(applied) == 0 {
			return nil
		}

		if state.Index.Height > s.spentElementRetentionBlocks {
			pruneHeight := state.Index.Height - s.spentElementRetentionBlocks

			bigfiles, err := pruneSpentBigfileElements(tx, pruneHeight)
			if err != nil {
				return fmt.Errorf("failed to cleanup bigfile elements: %w", err)
			}

			bigfunds, err := pruneSpentBigfundElements(tx, pruneHeight)
			if err != nil {
				return fmt.Errorf("failed to cleanup bigfund elements: %w", err)
			}
			log.Debug("pruned elements", zap.Int64("bigfiles", bigfiles), zap.Int64("bigfunds", bigfunds), zap.Uint64("pruneHeight", pruneHeight))
		}
		return nil
	})
}

// LastCommittedIndex returns the last chain index that was committed.
func (s *Store) LastCommittedIndex() (index types.ChainIndex, err error) {
	err = s.db.QueryRow(`SELECT last_indexed_height, last_indexed_id FROM global_settings`).Scan(&index.Height, decode(&index.ID))
	return
}

// ResetLastIndex resets the last indexed tip to trigger a full rescan.
func (s *Store) ResetLastIndex() error {
	_, err := s.db.Exec(`UPDATE global_settings SET last_indexed_height=0, last_indexed_id=$1`, encode(types.BlockID{}))
	return err
}

// IndexMode returns the current index mode.
func (s *Store) IndexMode() (wallet.IndexMode, error) {
	var mode wallet.IndexMode
	err := s.db.QueryRow(`SELECT index_mode FROM global_settings`).Scan(&mode)
	return mode, err
}

// SetIndexMode sets the index mode. If the index mode is already set, this
// function will return an error.
func (s *Store) SetIndexMode(mode wallet.IndexMode) error {
	return s.transaction(func(tx *txn) error {
		_, err := tx.Exec(`UPDATE global_settings SET index_mode=$1 WHERE index_mode IS NULL`, mode)
		if err != nil {
			return fmt.Errorf("failed to set index mode: %w", err)
		}

		// check that the index mode was set
		var existingMode wallet.IndexMode
		err = tx.QueryRow(`SELECT index_mode FROM global_settings`).Scan(&existingMode)
		if err != nil {
			return fmt.Errorf("failed to query index mode: %w", err)
		} else if existingMode != mode {
			return fmt.Errorf("cannot change index mode from %v to %v", existingMode, mode)
		}
		s.indexMode = mode // this is a bit annoying
		return nil
	})
}

// ResetChainState deletes all blockchain state from the database.
func (s *Store) ResetChainState() error {
	return s.transaction(func(tx *txn) error {
		_, err := tx.Exec(`UPDATE bigfile_addresses SET bigfile_balance=$1, bigfund_balance=0, immature_bigfile_balance=$1`, encode(types.ZeroCurrency))
		if err != nil {
			return fmt.Errorf("failed to reset bigfile addresses: %w", err)
		}

		_, err = tx.Exec(`DELETE FROM bigfile_elements`)
		if err != nil {
			return fmt.Errorf("failed to delete bigfile elements: %w", err)
		}

		_, err = tx.Exec(`DELETE FROM bigfund_elements`)
		if err != nil {
			return fmt.Errorf("failed to delete bigfund elements: %w", err)
		}

		_, err = tx.Exec(`DELETE FROM state_tree`)
		if err != nil {
			return fmt.Errorf("failed to delete state tree: %w", err)
		}

		_, err = tx.Exec(`DELETE FROM event_addresses`)
		if err != nil {
			return fmt.Errorf("failed to delete event addresses: %w", err)
		}

		_, err = tx.Exec(`DELETE FROM events`)
		if err != nil {
			return fmt.Errorf("failed to delete events: %w", err)
		}

		_, err = tx.Exec(`DELETE FROM chain_indices`)
		if err != nil {
			return fmt.Errorf("failed to delete chain indices: %w", err)
		}

		_, err = tx.Exec(`UPDATE global_settings SET last_indexed_height=0, last_indexed_id=$1, element_num_leaves=0`, encode(types.BlockID{}))
		if err != nil {
			return fmt.Errorf("failed to reset global settings: %w", err)
		}
		return nil
	})
}

func getBigfileStateElements(tx *txn) ([]stateElement, error) {
	const query = `SELECT id, leaf_index, merkle_proof FROM bigfile_elements`
	rows, err := tx.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query bigfile elements: %w", err)
	}
	defer rows.Close()

	var elements []stateElement
	for rows.Next() {
		var se stateElement
		if err := rows.Scan(decode(&se.ID), &se.LeafIndex, decode(&se.MerkleProof)); err != nil {
			return nil, fmt.Errorf("failed to scan bigfile element: %w", err)
		}
		elements = append(elements, se)
	}
	return elements, rows.Err()
}

func getBigfundStateElements(tx *txn) ([]stateElement, error) {
	const query = `SELECT id, leaf_index, merkle_proof FROM bigfund_elements`
	rows, err := tx.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query bigfund elements: %w", err)
	}
	defer rows.Close()

	var elements []stateElement
	for rows.Next() {
		var se stateElement
		if err := rows.Scan(decode(&se.ID), &se.LeafIndex, decode(&se.MerkleProof)); err != nil {
			return nil, fmt.Errorf("failed to scan bigfile element: %w", err)
		}
		elements = append(elements, se)
	}
	return elements, rows.Err()
}

func updateBigfundStateElements(tx *txn, elements []stateElement) error {
	if len(elements) == 0 {
		return nil
	}
	const query = `UPDATE bigfund_elements SET merkle_proof=$1, leaf_index=$2 WHERE id=$3`
	stmt, err := tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, se := range elements {
		res, err := stmt.Exec(encode(se.MerkleProof), se.LeafIndex, encode(se.ID))
		if err != nil {
			return fmt.Errorf("failed to execute statement: %w", err)
		} else if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		} else if n != 1 {
			return fmt.Errorf("expected 1 row affected, got %v", n)
		}
	}
	return nil
}

func updateBigfileStateElements(tx *txn, elements []stateElement) error {
	if len(elements) == 0 {
		return nil
	}
	const query = `UPDATE bigfile_elements SET merkle_proof=$1, leaf_index=$2 WHERE id=$3`
	stmt, err := tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, se := range elements {
		res, err := stmt.Exec(encode(se.MerkleProof), se.LeafIndex, encode(se.ID))
		if err != nil {
			return fmt.Errorf("failed to execute statement: %w", err)
		} else if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		} else if n != 1 {
			return fmt.Errorf("expected 1 row affected, got %v", n)
		}
	}
	return nil
}

func scanAddress(s scanner) (ab addressRef, err error) {
	err = s.Scan(&ab.ID, decode(&ab.Balance.Bigfiles), decode(&ab.Balance.ImmatureBigfiles), &ab.Balance.Bigfunds)
	return
}

func applyMatureBigfileBalance(tx *txn, index types.ChainIndex, log *zap.Logger) error {
	log = log.With(zap.Uint64("maturityHeight", index.Height))
	const query = `SELECT id, address_id, bigfile_value
FROM bigfile_elements
WHERE maturity_height=$1 AND matured=false AND spent_index_id IS NULL`
	rows, err := tx.Query(query, index.Height)
	if err != nil {
		return fmt.Errorf("failed to query bigfile elements: %w", err)
	}
	defer rows.Close()

	var matured []types.BigfileOutputID
	balanceDelta := make(map[int64]types.Currency)
	for rows.Next() {
		var outputID types.BigfileOutputID
		var addressID int64
		var value types.Currency

		if err := rows.Scan(decode(&outputID), &addressID, decode(&value)); err != nil {
			return fmt.Errorf("failed to scan bigfile balance: %w", err)
		}
		balanceDelta[addressID] = balanceDelta[addressID].Add(value)
		matured = append(matured, outputID)
		log.Debug("matured bigfile output", zap.Stringer("outputID", outputID), zap.Int64("addressID", addressID), zap.Stringer("value", value))
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to scan bigfile elements: %w", err)
	}

	updateMaturedStmt, err := tx.Prepare(`UPDATE bigfile_elements SET matured=true WHERE id=$1`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer updateMaturedStmt.Close()

	getAddressBalanceStmt, err := tx.Prepare(`SELECT bigfile_balance, immature_bigfile_balance FROM bigfile_addresses WHERE id=$1`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer getAddressBalanceStmt.Close()

	updateAddressBalanceStmt, err := tx.Prepare(`UPDATE bigfile_addresses SET bigfile_balance=$1, immature_bigfile_balance=$2 WHERE id=$3`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer updateAddressBalanceStmt.Close()

	for addressID, delta := range balanceDelta {
		var balance, immatureBalance types.Currency
		err := getAddressBalanceStmt.QueryRow(addressID).Scan(decode(&balance), decode(&immatureBalance))
		if err != nil {
			return fmt.Errorf("failed to get address balance: %w", err)
		}
		balance = balance.Add(delta)
		immatureBalance = immatureBalance.Sub(delta)

		res, err := updateAddressBalanceStmt.Exec(encode(balance), encode(immatureBalance), addressID)
		if err != nil {
			return fmt.Errorf("failed to update address balance: %w", err)
		} else if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		} else if n != 1 {
			return fmt.Errorf("expected 1 row affected, got %v", n)
		}
	}

	for _, id := range matured {
		res, err := updateMaturedStmt.Exec(encode(id))
		if err != nil {
			return fmt.Errorf("failed to update matured: %w", err)
		} else if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		} else if n != 1 {
			return fmt.Errorf("expected 1 row affected, got %v", n)
		}
	}
	return nil
}

func revertMatureBigfileBalance(tx *txn, index types.ChainIndex) error {
	const query = `SELECT se.id, se.address_id, se.bigfile_value
	FROM bigfile_elements se
	WHERE maturity_height=$1 AND matured=true AND spent_index_id IS NULL`
	rows, err := tx.Query(query, index.Height)
	if err != nil {
		return fmt.Errorf("failed to query bigfile elements: %w", err)
	}
	defer rows.Close()

	var matured []types.BigfileOutputID
	balanceDelta := make(map[int64]types.Currency)
	for rows.Next() {
		var outputID types.BigfileOutputID
		var addressID int64
		var value types.Currency

		if err := rows.Scan(decode(&outputID), &addressID, decode(&value)); err != nil {
			return fmt.Errorf("failed to scan bigfile balance: %w", err)
		}
		balanceDelta[addressID] = balanceDelta[addressID].Add(value)
		matured = append(matured, outputID)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to scan bigfile elements: %w", err)
	}

	updateMaturedStmt, err := tx.Prepare(`UPDATE bigfile_elements SET matured=false WHERE id=$1`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer updateMaturedStmt.Close()

	getAddressBalanceStmt, err := tx.Prepare(`SELECT bigfile_balance, immature_bigfile_balance FROM bigfile_addresses WHERE id=$1`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer getAddressBalanceStmt.Close()

	updateAddressBalanceStmt, err := tx.Prepare(`UPDATE bigfile_addresses SET bigfile_balance=$1, immature_bigfile_balance=$2 WHERE id=$3`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer updateAddressBalanceStmt.Close()

	for addressID, delta := range balanceDelta {
		var balance, immatureBalance types.Currency
		err := getAddressBalanceStmt.QueryRow(addressID).Scan(decode(&balance), decode(&immatureBalance))
		if err != nil {
			return fmt.Errorf("failed to get address balance: %w", err)
		}

		balance = balance.Sub(delta)
		immatureBalance = immatureBalance.Add(delta)

		res, err := updateAddressBalanceStmt.Exec(encode(balance), encode(immatureBalance), addressID)
		if err != nil {
			return fmt.Errorf("failed to update address balance: %w", err)
		} else if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		} else if n != 1 {
			return fmt.Errorf("expected 1 row affected, got %v", n)
		}
	}

	for _, id := range matured {
		res, err := updateMaturedStmt.Exec(encode(id))
		if err != nil {
			return fmt.Errorf("failed to update matured: %w", err)
		} else if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		} else if n != 1 {
			return fmt.Errorf("expected 1 row affected, got %v", n)
		}
	}
	return nil
}

func addBigfileElements(tx *txn, elements []types.BigfileElement, indexID int64, indexMode wallet.IndexMode, log *zap.Logger) error {
	if len(elements) == 0 {
		return nil
	}

	addressRefStmt, done, err := addressRefStmt(tx)
	if err != nil {
		return fmt.Errorf("failed to prepare address statement: %w", err)
	}
	defer done()

	existsStmt, err := tx.Prepare(`SELECT EXISTS(SELECT 1 FROM bigfile_elements WHERE id=$1)`)
	if err != nil {
		return fmt.Errorf("failed to prepare exists statement: %w", err)
	}
	defer existsStmt.Close()

	// ignore elements already in the database.
	insertStmt, err := tx.Prepare(`INSERT INTO bigfile_elements (id, bigfile_value, merkle_proof, leaf_index, maturity_height, address_id, matured, chain_index_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (id) DO UPDATE SET leaf_index=EXCLUDED.leaf_index, merkle_proof=EXCLUDED.merkle_proof`)
	if err != nil {
		return fmt.Errorf("failed to prepare insert statement: %w", err)
	}
	defer insertStmt.Close()

	balanceChanges := make(map[int64]wallet.Balance)
	for _, se := range elements {
		addrRef, err := addressRefStmt(se.BigfileOutput.Address)
		if err != nil {
			return fmt.Errorf("failed to query address: %w", err)
		} else if _, ok := balanceChanges[addrRef.ID]; !ok {
			balanceChanges[addrRef.ID] = addrRef.Balance
		}

		var exists bool
		err = existsStmt.QueryRow(encode(se.ID)).Scan(&exists)
		if err != nil {
			return fmt.Errorf("failed to check if bigfile element exists: %w", err)
		}

		// in full index mode, Merkle proofs are stored in the state tree table
		// rather than per element.
		if indexMode == wallet.IndexModeFull {
			se.StateElement.MerkleProof = nil
		}

		_, err = insertStmt.Exec(encode(se.ID), encode(se.BigfileOutput.Value), encode(se.StateElement.MerkleProof), se.StateElement.LeafIndex, se.MaturityHeight, addrRef.ID, se.MaturityHeight == 0, indexID)
		if err != nil {
			return fmt.Errorf("failed to execute statement: %w", err)
		}
		// skip balance update if the element already exists
		if exists {
			log.Debug("updated bigfile element", zap.Stringer("id", se.ID), zap.Stringer("address", se.BigfileOutput.Address), zap.Stringer("value", se.BigfileOutput.Value))
			continue
		}

		balance := balanceChanges[addrRef.ID]
		if se.MaturityHeight == 0 {
			balance.Bigfiles = balance.Bigfiles.Add(se.BigfileOutput.Value)
			log.Debug("added bigfile output", zap.Stringer("id", se.ID), zap.Stringer("address", se.BigfileOutput.Address), zap.Stringer("value", se.BigfileOutput.Value))
		} else {
			balance.ImmatureBigfiles = balance.ImmatureBigfiles.Add(se.BigfileOutput.Value)
			log.Debug("added immature bigfile output", zap.Stringer("id", se.ID), zap.Stringer("address", se.BigfileOutput.Address), zap.Stringer("value", se.BigfileOutput.Value), zap.Uint64("maturityHeight", se.MaturityHeight))
		}
		balanceChanges[addrRef.ID] = balance
	}

	if len(balanceChanges) == 0 {
		return nil
	}

	updateAddressBalanceStmt, err := tx.Prepare(`UPDATE bigfile_addresses SET bigfile_balance=$1, immature_bigfile_balance=$2 WHERE id=$3`)
	if err != nil {
		return fmt.Errorf("failed to prepare update balance statement: %w", err)
	}
	defer updateAddressBalanceStmt.Close()

	for addrID, balance := range balanceChanges {
		res, err := updateAddressBalanceStmt.Exec(encode(balance.Bigfiles), encode(balance.ImmatureBigfiles), addrID)
		if err != nil {
			return fmt.Errorf("failed to update balance: %w", err)
		} else if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		} else if n != 1 {
			return fmt.Errorf("expected 1 row affected, got %v", n)
		}
	}
	return nil
}

func removeBigfileElements(tx *txn, elements []types.BigfileElement) error {
	if len(elements) == 0 {
		return nil
	}

	addressRefStmt, done, err := addressRefStmt(tx)
	if err != nil {
		return fmt.Errorf("failed to prepare address statement: %w", err)
	}
	defer done()

	stmt, err := tx.Prepare(`DELETE FROM bigfile_elements WHERE id=$1 RETURNING id, matured`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	balanceChanges := make(map[int64]wallet.Balance)
	for _, se := range elements {
		addrRef, err := addressRefStmt(se.BigfileOutput.Address)
		if err != nil {
			return fmt.Errorf("failed to query address: %w", err)
		} else if _, ok := balanceChanges[addrRef.ID]; !ok {
			balanceChanges[addrRef.ID] = addrRef.Balance
		}

		var dummy types.Hash256
		var matured bool
		err = stmt.QueryRow(encode(se.ID)).Scan(decode(&dummy), &matured)
		if err != nil {
			return fmt.Errorf("failed to delete element %q: %w", se.ID, err)
		}

		balance := balanceChanges[addrRef.ID]
		if matured {
			balance.Bigfiles = balance.Bigfiles.Sub(se.BigfileOutput.Value)
		} else {
			balance.ImmatureBigfiles = balance.ImmatureBigfiles.Sub(se.BigfileOutput.Value)
		}
		balanceChanges[addrRef.ID] = balance
	}

	if len(balanceChanges) == 0 {
		return nil
	}

	updateAddressBalanceStmt, err := tx.Prepare(`UPDATE bigfile_addresses SET bigfile_balance=$1, immature_bigfile_balance=$2 WHERE id=$3`)
	if err != nil {
		return fmt.Errorf("failed to prepare update balance statement: %w", err)
	}
	defer updateAddressBalanceStmt.Close()

	for addrID, balance := range balanceChanges {
		res, err := updateAddressBalanceStmt.Exec(encode(balance.Bigfiles), encode(balance.ImmatureBigfiles), addrID)
		if err != nil {
			return fmt.Errorf("failed to update balance: %w", err)
		} else if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		} else if n != 1 {
			return fmt.Errorf("expected 1 row affected, got %v", n)
		}
	}
	return nil
}

func revertSpentBigfileElements(tx *txn, elements []types.BigfileElement) error {
	if len(elements) == 0 {
		return nil
	}

	addressRefStmt, done, err := addressRefStmt(tx)
	if err != nil {
		return fmt.Errorf("failed to prepare address statement: %w", err)
	}
	defer done()

	stmt, err := tx.Prepare(`UPDATE bigfile_elements SET spent_index_id=NULL, spent_event_id=NULL WHERE id=$1 AND spent_index_id IS NOT NULL RETURNING id`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	balanceChanges := make(map[int64]wallet.Balance)
	for _, se := range elements {
		addrRef, err := addressRefStmt(se.BigfileOutput.Address)
		if err != nil {
			return fmt.Errorf("failed to query address: %w", err)
		} else if _, ok := balanceChanges[addrRef.ID]; !ok {
			balanceChanges[addrRef.ID] = addrRef.Balance
		}

		var dummy types.Hash256
		if err := stmt.QueryRow(encode(se.ID)).Scan(decode(&dummy)); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		} else if errors.Is(err, sql.ErrNoRows) {
			continue // skip if the element does not exist
		}

		balance := balanceChanges[addrRef.ID]
		balance.Bigfiles = balance.Bigfiles.Add(se.BigfileOutput.Value)
		balanceChanges[addrRef.ID] = balance
	}

	if len(balanceChanges) == 0 {
		return nil
	}

	updateAddressBalanceStmt, err := tx.Prepare(`UPDATE bigfile_addresses SET bigfile_balance=$1 WHERE id=$2`)
	if err != nil {
		return fmt.Errorf("failed to prepare update balance statement: %w", err)
	}
	defer updateAddressBalanceStmt.Close()

	for addrID, balance := range balanceChanges {
		res, err := updateAddressBalanceStmt.Exec(encode(balance.Bigfiles), addrID)
		if err != nil {
			return fmt.Errorf("failed to update balance: %w", err)
		} else if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		} else if n != 1 {
			return fmt.Errorf("expected 1 row affected, got %v", n)
		}
	}
	return nil
}

func spendBigfileElements(tx *txn, elements []wallet.SpentBigfileElement, indexID int64) error {
	if len(elements) == 0 {
		return nil
	}

	addressRefStmt, done, err := addressRefStmt(tx)
	if err != nil {
		return fmt.Errorf("failed to prepare address statement: %w", err)
	}
	defer done()

	getEventIDStmt, err := tx.Prepare(`SELECT id FROM events WHERE event_id=$1`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer getEventIDStmt.Close()

	stmt, err := tx.Prepare(`UPDATE bigfile_elements SET spent_index_id=$1, spent_event_id=$2 WHERE id=$3 AND spent_index_id IS NULL RETURNING id`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	balanceChanges := make(map[int64]wallet.Balance)
	for _, se := range elements {
		addrRef, err := addressRefStmt(se.BigfileOutput.Address)
		if err != nil {
			return fmt.Errorf("failed to query address: %w", err)
		} else if _, ok := balanceChanges[addrRef.ID]; !ok {
			balanceChanges[addrRef.ID] = addrRef.Balance
		}

		var eventDBID int64
		if err := getEventIDStmt.QueryRow(encode(se.EventID)).Scan(&eventDBID); err != nil {
			return fmt.Errorf("failed to get event ID: %w", err)
		}

		var dummy types.Hash256
		if err := stmt.QueryRow(indexID, eventDBID, encode(se.ID)).Scan(decode(&dummy)); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		} else if errors.Is(err, sql.ErrNoRows) {
			continue // skip if the element does not exist
		}

		balance := balanceChanges[addrRef.ID]
		balance.Bigfiles = balance.Bigfiles.Sub(se.BigfileOutput.Value)
		balanceChanges[addrRef.ID] = balance
	}

	if len(balanceChanges) == 0 {
		return nil
	}

	updateAddressBalanceStmt, err := tx.Prepare(`UPDATE bigfile_addresses SET bigfile_balance=$1 WHERE id=$2`)
	if err != nil {
		return fmt.Errorf("failed to prepare update balance statement: %w", err)
	}
	defer updateAddressBalanceStmt.Close()

	for addrID, balance := range balanceChanges {
		res, err := updateAddressBalanceStmt.Exec(encode(balance.Bigfiles), addrID)
		if err != nil {
			return fmt.Errorf("failed to update balance: %w", err)
		} else if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		} else if n != 1 {
			return fmt.Errorf("expected 1 row affected, got %v", n)
		}
	}
	return nil
}

func addBigfundElements(tx *txn, elements []types.BigfundElement, indexID int64, indexMode wallet.IndexMode, log *zap.Logger) error {
	if len(elements) == 0 {
		return nil
	}

	addressRefStmt, done, err := addressRefStmt(tx)
	if err != nil {
		return fmt.Errorf("failed to prepare address statement: %w", err)
	}
	defer done()

	existsStmt, err := tx.Prepare(`SELECT EXISTS(SELECT 1 FROM bigfund_elements WHERE id=$1)`)
	if err != nil {
		return fmt.Errorf("failed to prepare exists statement: %w", err)
	}
	defer existsStmt.Close()

	insertStmt, err := tx.Prepare(`INSERT INTO bigfund_elements (id, bigfund_value, merkle_proof, leaf_index, claim_start, address_id, chain_index_id) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id) DO UPDATE SET leaf_index=EXCLUDED.leaf_index, merkle_proof=EXCLUDED.merkle_proof`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer insertStmt.Close()

	balanceChanges := make(map[int64]uint64)
	for _, se := range elements {
		addrRef, err := addressRefStmt(se.BigfundOutput.Address)
		if err != nil {
			return fmt.Errorf("failed to query address: %w", err)
		} else if _, ok := balanceChanges[addrRef.ID]; !ok {
			balanceChanges[addrRef.ID] = addrRef.Balance.Bigfunds
		}

		var exists bool
		if err := existsStmt.QueryRow(encode(se.ID)).Scan(&exists); err != nil {
			return fmt.Errorf("failed to check if bigfund element exists: %w", err)
		}

		// in full index mode, Merkle proofs are stored in the state tree table
		// rather than per element.
		if indexMode == wallet.IndexModeFull {
			se.StateElement.MerkleProof = nil
		}

		_, err = insertStmt.Exec(encode(se.ID), se.BigfundOutput.Value, encode(se.StateElement.MerkleProof), se.StateElement.LeafIndex, encode(se.ClaimStart), addrRef.ID, indexID)
		if err != nil {
			return fmt.Errorf("failed to execute statement: %w", err)
		} else if exists {
			// skip balance update if the element already exists
			log.Debug("updated bigfund element", zap.Stringer("id", se.ID), zap.Stringer("address", se.BigfundOutput.Address), zap.Uint64("value", se.BigfundOutput.Value))
			continue
		}
		balanceChanges[addrRef.ID] += se.BigfundOutput.Value
	}

	if len(balanceChanges) == 0 {
		return nil
	}

	updateAddressBalanceStmt, err := tx.Prepare(`UPDATE bigfile_addresses SET bigfund_balance=$1 WHERE id=$2`)
	if err != nil {
		return fmt.Errorf("failed to prepare update balance statement: %w", err)
	}
	defer updateAddressBalanceStmt.Close()

	for addrID, balance := range balanceChanges {
		res, err := updateAddressBalanceStmt.Exec(balance, addrID)
		if err != nil {
			return fmt.Errorf("failed to update balance: %w", err)
		} else if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		} else if n != 1 {
			return fmt.Errorf("expected 1 row affected, got %v", n)
		}
	}
	return nil
}

func removeBigfundElements(tx *txn, elements []types.BigfundElement) error {
	if len(elements) == 0 {
		return nil
	}

	addressRefStmt, done, err := addressRefStmt(tx)
	if err != nil {
		return fmt.Errorf("failed to prepare address statement: %w", err)
	}
	defer done()

	stmt, err := tx.Prepare(`DELETE FROM bigfund_elements WHERE id=$1 RETURNING id`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	balanceChanges := make(map[int64]uint64)
	for _, se := range elements {
		addrRef, err := addressRefStmt(se.BigfundOutput.Address)
		if err != nil {
			return fmt.Errorf("failed to query address: %w", err)
		} else if _, ok := balanceChanges[addrRef.ID]; !ok {
			balanceChanges[addrRef.ID] = addrRef.Balance.Bigfunds
		}

		var dummy types.Hash256
		err = stmt.QueryRow(encode(se.ID)).Scan(decode(&dummy))
		if err != nil {
			return fmt.Errorf("failed to delete element %q: %w", se.ID, err)
		}

		if balanceChanges[addrRef.ID] < se.BigfundOutput.Value {
			panic("bigfund balance cannot be negative")
		}
		balanceChanges[addrRef.ID] -= se.BigfundOutput.Value
	}

	if len(balanceChanges) == 0 {
		return nil
	}

	updateAddressBalanceStmt, err := tx.Prepare(`UPDATE bigfile_addresses SET bigfund_balance=$1 WHERE id=$2`)
	if err != nil {
		return fmt.Errorf("failed to prepare update balance statement: %w", err)
	}
	defer updateAddressBalanceStmt.Close()

	for addrID, balance := range balanceChanges {
		res, err := updateAddressBalanceStmt.Exec(balance, addrID)
		if err != nil {
			return fmt.Errorf("failed to update balance: %w", err)
		} else if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		} else if n != 1 {
			return fmt.Errorf("expected 1 row affected, got %v", n)
		}
	}
	return nil
}

func spendBigfundElements(tx *txn, elements []wallet.SpentBigfundElement, indexID int64) error {
	if len(elements) == 0 {
		return nil
	}

	addressRefStmt, done, err := addressRefStmt(tx)
	if err != nil {
		return fmt.Errorf("failed to prepare address statement: %w", err)
	}
	defer done()

	getEventIDStmt, err := tx.Prepare(`SELECT id FROM events WHERE event_id=$1`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer getEventIDStmt.Close()

	stmt, err := tx.Prepare(`UPDATE bigfund_elements SET spent_index_id=$1, spent_event_id=$2 WHERE id=$3 AND spent_index_id IS NULL RETURNING id`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	balanceChanges := make(map[int64]wallet.Balance)
	for _, se := range elements {
		addrRef, err := addressRefStmt(se.BigfundOutput.Address)
		if err != nil {
			return fmt.Errorf("failed to query address: %w", err)
		} else if _, ok := balanceChanges[addrRef.ID]; !ok {
			balanceChanges[addrRef.ID] = addrRef.Balance
		}

		var eventDBID int64
		if err := getEventIDStmt.QueryRow(encode(se.EventID)).Scan(&eventDBID); err != nil {
			return fmt.Errorf("failed to get event ID: %w", err)
		}

		var dummy types.Hash256
		if err := stmt.QueryRow(indexID, eventDBID, encode(se.ID)).Scan(decode(&dummy)); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		} else if errors.Is(err, sql.ErrNoRows) {
			continue // skip if the element does not exist
		}

		balance := balanceChanges[addrRef.ID]
		if balance.Bigfunds < se.BigfundOutput.Value {
			panic("bigfund balance cannot be negative")
		}
		balance.Bigfunds -= se.BigfundOutput.Value

		balanceChanges[addrRef.ID] = balance
	}

	if len(balanceChanges) == 0 {
		return nil
	}

	updateAddressBalanceStmt, err := tx.Prepare(`UPDATE bigfile_addresses SET bigfund_balance=$1 WHERE id=$3`)
	if err != nil {
		return fmt.Errorf("failed to prepare update balance statement: %w", err)
	}
	defer updateAddressBalanceStmt.Close()

	for addrID, balance := range balanceChanges {
		res, err := updateAddressBalanceStmt.Exec(balance.Bigfunds, addrID)
		if err != nil {
			return fmt.Errorf("failed to update balance: %w", err)
		} else if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		} else if n != 1 {
			return fmt.Errorf("expected 1 row affected, got %v", n)
		}
	}
	return nil
}

func revertSpentBigfundElements(tx *txn, elements []types.BigfundElement) error {
	if len(elements) == 0 {
		return nil
	}

	addressRefStmt, done, err := addressRefStmt(tx)
	if err != nil {
		return fmt.Errorf("failed to prepare address statement: %w", err)
	}
	defer done()

	stmt, err := tx.Prepare(`UPDATE bigfund_elements SET spent_index_id=NULL, spent_event_id=NULL WHERE id=$1 AND spent_index_id IS NOT NULL RETURNING id`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	balanceChanges := make(map[int64]wallet.Balance)
	for _, se := range elements {
		addrRef, err := addressRefStmt(se.BigfundOutput.Address)
		if err != nil {
			return fmt.Errorf("failed to query address: %w", err)
		} else if _, ok := balanceChanges[addrRef.ID]; !ok {
			balanceChanges[addrRef.ID] = addrRef.Balance
		}

		var dummy types.Hash256
		if err := stmt.QueryRow(encode(se.ID)).Scan(decode(&dummy)); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		} else if errors.Is(err, sql.ErrNoRows) {
			continue // skip if the element does not exist
		}

		balance := balanceChanges[addrRef.ID]
		balance.Bigfunds += se.BigfundOutput.Value
		balanceChanges[addrRef.ID] = balance
	}

	if len(balanceChanges) == 0 {
		return nil
	}

	updateAddressBalanceStmt, err := tx.Prepare(`UPDATE bigfile_addresses SET bigfund_balance=$1 WHERE id=$3`)
	if err != nil {
		return fmt.Errorf("failed to prepare update balance statement: %w", err)
	}
	defer updateAddressBalanceStmt.Close()

	for addrID, balance := range balanceChanges {
		res, err := updateAddressBalanceStmt.Exec(balance.Bigfunds, addrID)
		if err != nil {
			return fmt.Errorf("failed to update balance: %w", err)
		} else if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		} else if n != 1 {
			return fmt.Errorf("expected 1 row affected, got %v", n)
		}
	}
	return nil
}

func addEvents(tx *txn, events []wallet.Event, indexID int64) error {
	if len(events) == 0 {
		return nil
	}

	insertEventStmt, err := tx.Prepare(`INSERT INTO events (event_id, maturity_height, date_created, event_type, event_data, chain_index_id) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (event_id) DO NOTHING RETURNING id`)
	if err != nil {
		return fmt.Errorf("failed to prepare event statement: %w", err)
	}
	defer insertEventStmt.Close()

	addrStmt, err := tx.Prepare(`INSERT INTO bigfile_addresses (bigfile_address, bigfile_balance, immature_bigfile_balance, bigfund_balance) VALUES ($1, $2, $2, 0) ON CONFLICT (bigfile_address) DO UPDATE SET bigfile_address=EXCLUDED.bigfile_address RETURNING id`)
	if err != nil {
		return fmt.Errorf("failed to prepare address statement: %w", err)
	}
	defer addrStmt.Close()

	relevantAddrStmt, err := tx.Prepare(`INSERT INTO event_addresses (event_id, address_id, event_maturity_height) VALUES ($1, $2, $3) ON CONFLICT (event_id, address_id) DO NOTHING`)
	if err != nil {
		return fmt.Errorf("failed to prepare relevant address statement: %w", err)
	}
	defer relevantAddrStmt.Close()

	var buf bytes.Buffer
	enc := types.NewEncoder(&buf)
	for _, event := range events {
		buf.Reset()
		ev, ok := event.Data.(types.EncoderTo)
		if !ok {
			panic("event data does not implement types.EncoderTo") // developer error
		}
		ev.EncodeTo(enc)
		enc.Flush()

		var eventID int64
		err = insertEventStmt.QueryRow(encode(event.ID), event.MaturityHeight, encode(event.Timestamp), event.Type, buf.Bytes(), indexID).Scan(&eventID)
		if errors.Is(err, sql.ErrNoRows) {
			continue // skip if the event already exists
		} else if err != nil {
			return fmt.Errorf("failed to add event: %w", err)
		}

		used := make(map[types.Address]bool)
		for _, addr := range event.Relevant {
			if used[addr] {
				continue
			}

			var addressID int64
			err = addrStmt.QueryRow(encode(addr), encode(types.ZeroCurrency)).Scan(&addressID)
			if err != nil {
				return fmt.Errorf("failed to get address: %w", err)
			}

			_, err = relevantAddrStmt.Exec(eventID, addressID, event.MaturityHeight)
			if err != nil {
				return fmt.Errorf("failed to add relevant address: %w", err)
			}

			used[addr] = true
		}
	}
	return nil
}

// RevertEvents reverts any events that were added by the index
func revertEvents(tx *txn, index types.ChainIndex) error {
	const query = `DELETE FROM events WHERE chain_index_id IN (SELECT id FROM chain_indices WHERE block_id=$1 AND height=$2)`
	_, err := tx.Exec(query, encode(index.ID), index.Height)
	return err
}

func revertSpentOrphanedBigfileElements(tx *txn, index types.ChainIndex, log *zap.Logger) (map[int64]wallet.Balance, error) {
	rows, err := tx.Query(`UPDATE bigfile_elements SET spent_index_id=NULL, spent_event_id=NULL WHERE id IN (SELECT se.id FROM bigfile_elements se
INNER JOIN chain_indices ci ON (ci.id=se.spent_index_id)
WHERE ci.height=$1 AND ci.block_id<>$2)
RETURNING address_id, bigfile_value`, index.Height, encode(index.ID))
	if err != nil {
		return nil, fmt.Errorf("failed to query bigfile elements: %w", err)
	}
	defer rows.Close()

	balances := make(map[int64]wallet.Balance)
	for rows.Next() {
		var addrID int64
		var value types.Currency

		if err := rows.Scan(&addrID, decode(&value)); err != nil {
			return nil, fmt.Errorf("failed to scan bigfile element: %w", err)
		}

		balance := balances[addrID]
		balance.Bigfiles = balance.Bigfiles.Add(value)
		balances[addrID] = balance
		log.Debug("reverting spent orphaned bigfile element", zap.Stringer("value", value))
	}
	return balances, rows.Err()
}

func deleteOrphanedBigfileElements(tx *txn, index types.ChainIndex, log *zap.Logger) (map[int64]wallet.Balance, error) {
	rows, err := tx.Query(`DELETE FROM bigfile_elements WHERE id IN (SELECT se.id FROM bigfile_elements se
INNER JOIN chain_indices ci ON (ci.id=se.chain_index_id)
WHERE ci.height=$1 AND ci.block_id<>$2)
RETURNING id, address_id, bigfile_value, matured, spent_index_id IS NOT NULL`, index.Height, encode(index.ID))
	if err != nil {
		return nil, fmt.Errorf("failed to query bigfile elements: %w", err)
	}
	defer rows.Close()

	balances := make(map[int64]wallet.Balance)
	for rows.Next() {
		var outputID types.BigfileOutputID
		var addrID int64
		var value types.Currency
		var matured bool
		var spent bool

		if err := rows.Scan(decode(&outputID), &addrID, decode(&value), &matured, &spent); err != nil {
			return nil, fmt.Errorf("failed to scan bigfile element: %w", err)
		}

		balance := balances[addrID]
		if !matured {
			balance.ImmatureBigfiles = balance.ImmatureBigfiles.Add(value)
		} else if !spent {
			balance.Bigfiles = balance.Bigfiles.Add(value)
		}
		balances[addrID] = balance
		log.Debug("deleting orphaned bigfile element", zap.Stringer("id", outputID), zap.Stringer("value", value), zap.Bool("matured", matured), zap.Bool("spent", spent))
	}
	return balances, rows.Err()
}

func revertSpentOrphanedBigfundElements(tx *txn, index types.ChainIndex, log *zap.Logger) (map[int64]uint64, error) {
	rows, err := tx.Query(`UPDATE bigfund_elements SET spent_index_id=NULL, spent_event_id=NULL WHERE id IN (SELECT se.id FROM bigfund_elements se
INNER JOIN chain_indices ci ON (ci.id=se.spent_index_id)
WHERE ci.height=$1 AND ci.block_id<>$2)
RETURNING id, address_id, bigfund_value`, index.Height, encode(index.ID))
	if err != nil {
		return nil, fmt.Errorf("failed to query bigfund elements: %w", err)
	}
	defer rows.Close()

	balances := make(map[int64]uint64)
	for rows.Next() {
		var outputID types.BigfundOutputID
		var addrID int64
		var value uint64

		if err := rows.Scan(decode(&outputID), &addrID, value); err != nil {
			return nil, fmt.Errorf("failed to scan bigfund element: %w", err)
		}

		balance := balances[addrID]
		balance += value
		balances[addrID] = balance
		log.Debug("reverting spent orphaned bigfund element", zap.Stringer("id", outputID), zap.Uint64("value", value))
	}
	return balances, rows.Err()
}

func deleteOrphanedBigfundElements(tx *txn, index types.ChainIndex, log *zap.Logger) (map[int64]uint64, error) {
	rows, err := tx.Query(`DELETE FROM bigfund_elements WHERE id IN (SELECT se.id FROM bigfund_elements se
INNER JOIN chain_indices ci ON (ci.id=se.chain_index_id)
WHERE ci.height=$1 AND ci.block_id<>$2)
RETURNING id, address_id, bigfund_value, spent_index_id IS NOT NULL`, index.Height, encode(index.ID))
	if err != nil {
		return nil, fmt.Errorf("failed to query bigfund elements: %w", err)
	}
	defer rows.Close()

	balances := make(map[int64]uint64)
	for rows.Next() {
		var outputID types.BigfundOutputID
		var addrID int64
		var value uint64
		var spent bool

		if err := rows.Scan(decode(&outputID), &addrID, &value, &spent); err != nil {
			return nil, fmt.Errorf("failed to scan bigfund element: %w", err)
		}
		balances[addrID] += value
		log.Debug("deleting orphaned bigfund element", zap.Stringer("id", outputID), zap.Uint64("value", value), zap.Bool("spent", spent))
	}
	return balances, rows.Err()
}

func deleteOrphanedEvents(tx *txn, index types.ChainIndex) error {
	_, err := tx.Exec(`DELETE FROM events WHERE id IN (SELECT ev.id FROM events ev
INNER JOIN chain_indices ci ON (ev.chain_index_id=ci.id)
WHERE ci.height=$1 AND ci.block_id<>$2);`, index.Height, encode(index.ID))
	return err
}

// revertOrphans reverts any chain indices that were orphaned by the given index
func revertOrphans(tx *txn, index types.ChainIndex, log *zap.Logger) error {
	// fetch orphaned bigfile balances
	deletedBigfiles, err := deleteOrphanedBigfileElements(tx, index, log.Named("deleteOrphanedBigfileElements"))
	if err != nil {
		return fmt.Errorf("failed to get orphaned bigfile elements: %w", err)
	}

	// fetch orphaned bigfund balances
	deletedBigfunds, err := deleteOrphanedBigfundElements(tx, index, log.Named("deleteOrphanedBigfundElements"))
	if err != nil {
		return fmt.Errorf("failed to get orphaned bigfund elements: %w", err)
	}

	unspentBigfiles, err := revertSpentOrphanedBigfileElements(tx, index, log.Named("revertSpentOrphanedBigfileElements"))
	if err != nil {
		return fmt.Errorf("failed to revert spent orphaned bigfile elements: %w", err)
	}

	unspentBigfunds, err := revertSpentOrphanedBigfundElements(tx, index, log.Named("revertSpentOrphanedBigfundElements"))
	if err != nil {
		return fmt.Errorf("failed to revert spent orphaned bigfund elements: %w", err)
	}

	// get the addrIDs of all affected addresses
	addrIDs := make(map[int64]bool)
	for id := range deletedBigfiles {
		addrIDs[id] = true
	}
	for id := range deletedBigfunds {
		addrIDs[id] = true
	}
	for id := range unspentBigfiles {
		addrIDs[id] = true
	}
	for id := range unspentBigfunds {
		addrIDs[id] = true
	}

	getBalanceStmt, err := tx.Prepare(`SELECT bigfile_balance, immature_bigfile_balance, bigfund_balance FROM bigfile_addresses WHERE id=$1`)
	if err != nil {
		return fmt.Errorf("failed to prepare balance statement: %w", err)
	}
	defer getBalanceStmt.Close()

	updateBalanceStmt, err := tx.Prepare(`UPDATE bigfile_addresses SET bigfile_balance=$1, immature_bigfile_balance=$2, bigfund_balance=$3 WHERE id=$4`)
	if err != nil {
		return fmt.Errorf("failed to prepare update statement: %w", err)
	}
	defer updateBalanceStmt.Close()

	for addrID := range addrIDs {
		var existing wallet.Balance
		err := getBalanceStmt.QueryRow(addrID).Scan(decode(&existing.Bigfiles), decode(&existing.ImmatureBigfiles), &existing.Bigfunds)
		if err != nil {
			return fmt.Errorf("failed to get balance: %w", err)
		}

		existing.Bigfiles = existing.Bigfiles.Sub(deletedBigfiles[addrID].Bigfiles)
		existing.ImmatureBigfiles = existing.ImmatureBigfiles.Sub(deletedBigfiles[addrID].ImmatureBigfiles)
		if existing.Bigfunds < deletedBigfunds[addrID] {
			panic("bigfund balance cannot be negative")
		}
		existing.Bigfunds -= deletedBigfunds[addrID]

		existing.Bigfiles = existing.Bigfiles.Add(unspentBigfiles[addrID].Bigfiles)
		existing.Bigfunds += unspentBigfunds[addrID]

		res, err := updateBalanceStmt.Exec(encode(existing.Bigfiles), encode(existing.ImmatureBigfiles), existing.Bigfunds, addrID)
		if err != nil {
			return fmt.Errorf("failed to update balance: %w", err)
		} else if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		} else if n != 1 {
			return fmt.Errorf("expected 1 row affected, got %v", n)
		}
	}

	if err := deleteOrphanedEvents(tx, index); err != nil {
		return fmt.Errorf("failed to delete orphaned events: %w", err)
	}

	_, err = tx.Exec(`DELETE FROM chain_indices WHERE height=$1 AND block_id<>$2`, index.Height, encode(index.ID))
	return err
}

func pruneSpentBigfileElements(tx *txn, height uint64) (removed int64, err error) {
	const query = `DELETE FROM bigfile_elements WHERE spent_index_id IN (SELECT id FROM chain_indices WHERE height <= $1)`
	res, err := tx.Exec(query, height)
	if err != nil {
		return 0, fmt.Errorf("failed to query bigfile elements: %w", err)
	}
	return res.RowsAffected()
}

func pruneSpentBigfundElements(tx *txn, height uint64) (removed int64, err error) {
	const query = `DELETE FROM bigfund_elements WHERE spent_index_id IN (SELECT id FROM chain_indices WHERE height <= $1)`
	res, err := tx.Exec(query, height)
	if err != nil {
		return 0, fmt.Errorf("failed to query bigfile elements: %w", err)
	}
	return res.RowsAffected()
}

func setGlobalState(tx *txn, index types.ChainIndex, numLeaves uint64) error {
	_, err := tx.Exec(`UPDATE global_settings SET last_indexed_height=$1, last_indexed_id=$2, element_num_leaves=$3`, index.Height, encode(index.ID), numLeaves)
	return err
}

func addressRefStmt(tx *txn) (func(types.Address) (addressRef, error), func() error, error) {
	stmt, err := tx.Prepare(`INSERT INTO bigfile_addresses (bigfile_address, bigfile_balance, immature_bigfile_balance, bigfund_balance) VALUES ($1, $2, $3, $4) ON CONFLICT (bigfile_address) DO UPDATE SET bigfile_address=EXCLUDED.bigfile_address RETURNING id, bigfile_balance, immature_bigfile_balance, bigfund_balance`)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare address statement: %w", err)
	}
	// the on conflict is effectively a no-op, but enables us to return the id of the existing address
	return func(addr types.Address) (addressRef, error) {
		ref, err := scanAddress(stmt.QueryRow(encode(addr), encode(types.ZeroCurrency), encode(types.ZeroCurrency), 0))
		if err != nil {
			return addressRef{}, fmt.Errorf("failed to get address %q: %w", addr, err)
		}
		return ref, nil
	}, stmt.Close, nil
}
