package sqlite

import (
	"database/sql"
	"errors"
	"fmt"

	"go.thebigfile.com/core/types"
	"go.thebigfile.com/walletd/v2/wallet"
)

func getBigfileElement(tx *txn, id types.BigfileOutputID, indexMode wallet.IndexMode) (ele types.BigfileElement, err error) {
	const query = `SELECT se.id, se.bigfile_value, se.merkle_proof, se.leaf_index, se.maturity_height, sa.bigfile_address 
FROM bigfile_elements se
INNER JOIN bigfile_addresses sa ON (se.address_id = sa.id)
WHERE se.id=$1 AND spent_index_id IS NULL`

	ele, err = scanBigfileElement(tx.QueryRow(query, encode(id)))
	if err != nil {
		return types.BigfileElement{}, err
	}

	// retrieve the merkle proofs for the bigfile element
	if indexMode == wallet.IndexModeFull {
		proof, err := fillElementProofs(tx, []uint64{ele.StateElement.LeafIndex})
		if err != nil {
			return types.BigfileElement{}, fmt.Errorf("failed to fill element proofs: %w", err)
		} else if len(proof) != 1 {
			panic("expected exactly one proof") // should never happen
		}
		ele.StateElement.MerkleProof = proof[0]
	}
	return
}

func getBigfundElement(tx *txn, id types.BigfundOutputID, indexMode wallet.IndexMode) (ele types.BigfundElement, err error) {
	const query = `SELECT se.id, se.leaf_index, se.merkle_proof, se.bigfund_value, se.claim_start, sa.bigfile_address 
FROM bigfund_elements se
INNER JOIN bigfile_addresses sa ON (se.address_id = sa.id)
WHERE se.id=$1 AND spent_index_id IS NULL`

	ele, err = scanBigfundElement(tx.QueryRow(query, encode(id)))
	if err != nil {
		return types.BigfundElement{}, err
	}

	// retrieve the merkle proofs for the bigfund element
	if indexMode == wallet.IndexModeFull {
		proof, err := fillElementProofs(tx, []uint64{ele.StateElement.LeafIndex})
		if err != nil {
			return types.BigfundElement{}, fmt.Errorf("failed to fill element proofs: %w", err)
		} else if len(proof) != 1 {
			panic("expected exactly one proof") // should never happen
		}
		ele.StateElement.MerkleProof = proof[0]
	}
	return
}

// BigfileElement returns an unspent Bigfile UTXO by its ID.
func (s *Store) BigfileElement(id types.BigfileOutputID) (ele types.BigfileElement, err error) {
	err = s.transaction(func(tx *txn) error {
		ele, err = getBigfileElement(tx, id, s.indexMode)
		if errors.Is(err, sql.ErrNoRows) {
			return wallet.ErrNotFound
		}
		return err
	})
	return
}

// BigfundElement returns an unspent Bigfund UTXO by its ID.
func (s *Store) BigfundElement(id types.BigfundOutputID) (ele types.BigfundElement, err error) {
	err = s.transaction(func(tx *txn) error {
		ele, err = getBigfundElement(tx, id, s.indexMode)
		if errors.Is(err, sql.ErrNoRows) {
			return wallet.ErrNotFound
		}
		return err
	})
	return
}

// BigfileElementSpentEvent returns the event that spent a Bigfile UTXO.
func (s *Store) BigfileElementSpentEvent(id types.BigfileOutputID) (ev wallet.Event, spent bool, err error) {
	err = s.transaction(func(tx *txn) error {
		const query = `SELECT spent_event_id FROM bigfile_elements WHERE id=$1`

		var spentEventID sql.NullInt64
		err = tx.QueryRow(query, encode(id)).Scan(&spentEventID)
		if errors.Is(err, sql.ErrNoRows) {
			return wallet.ErrNotFound
		} else if err != nil {
			return fmt.Errorf("failed to query spent event ID: %w", err)
		} else if !spentEventID.Valid {
			return nil
		}

		spent = true
		events, err := getEventsByID(tx, []int64{spentEventID.Int64})
		if err != nil {
			return fmt.Errorf("failed to get events by ID: %w", err)
		} else if len(events) != 1 {
			panic("expected exactly one event") // should never happen
		}
		ev = events[0]
		return nil
	})
	return
}

// BigfundElementSpentEvent returns the event that spent a Bigfund UTXO.
func (s *Store) BigfundElementSpentEvent(id types.BigfundOutputID) (ev wallet.Event, spent bool, err error) {
	err = s.transaction(func(tx *txn) error {
		const query = `SELECT spent_event_id FROM bigfund_elements WHERE id=$1`

		var spentEventID sql.NullInt64
		err = tx.QueryRow(query, encode(id)).Scan(&spentEventID)
		if errors.Is(err, sql.ErrNoRows) {
			return wallet.ErrNotFound
		} else if err != nil {
			return fmt.Errorf("failed to query spent event ID: %w", err)
		} else if !spentEventID.Valid {
			return nil
		}

		spent = true
		events, err := getEventsByID(tx, []int64{spentEventID.Int64})
		if err != nil {
			return fmt.Errorf("failed to get events by ID: %w", err)
		} else if len(events) != 1 {
			panic("expected exactly one event") // should never happen
		}
		ev = events[0]
		return nil
	})

	return
}
