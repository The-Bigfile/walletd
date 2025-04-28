package sqlite

import (
	"database/sql"
	"errors"
	"fmt"

	"go.thebigfile.com/core/types"
	"go.thebigfile.com/walletd/v2/wallet"
)

// BigFileElement returns an unspent BigFile UTXO by its ID.
func (s *Store) BigFileElement(id types.BigFileOutputID) (ele types.BigFileElement, err error) {
	err = s.transaction(func(tx *txn) error {
		const query = `SELECT se.id, se.bigfile_value, se.merkle_proof, se.leaf_index, se.maturity_height, sa.sia_address 
FROM bigfile_elements se
INNER JOIN sia_addresses sa ON (se.address_id = sa.id)
WHERE se.id=$1 AND spent_index_id IS NULL`

		ele, err = scanBigFileElement(tx.QueryRow(query, encode(id)))
		if err != nil {
			return err
		}

		// retrieve the merkle proofs for the bigfile element
		if s.indexMode == wallet.IndexModeFull {
			proof, err := fillElementProofs(tx, []uint64{ele.StateElement.LeafIndex})
			if err != nil {
				return fmt.Errorf("failed to fill element proofs: %w", err)
			} else if len(proof) != 1 {
				panic("expected exactly one proof") // should never happen
			}
			ele.StateElement.MerkleProof = proof[0]
		}
		return nil
	})
	if errors.Is(err, sql.ErrNoRows) {
		err = wallet.ErrNotFound
	}
	return
}

// SiafundElement returns an unspent Siafund UTXO by its ID.
func (s *Store) SiafundElement(id types.SiafundOutputID) (ele types.SiafundElement, err error) {
	err = s.transaction(func(tx *txn) error {
		const query = `SELECT se.id, se.leaf_index, se.merkle_proof, se.siafund_value, se.claim_start, sa.sia_address 
FROM siafund_elements se
INNER JOIN sia_addresses sa ON (se.address_id = sa.id)
WHERE se.id=$1 AND spent_index_id IS NULL`

		ele, err = scanSiafundElement(tx.QueryRow(query, encode(id)))
		if err != nil {
			return err
		}

		// retrieve the merkle proofs for the siafund element
		if s.indexMode == wallet.IndexModeFull {
			proof, err := fillElementProofs(tx, []uint64{ele.StateElement.LeafIndex})
			if err != nil {
				return fmt.Errorf("failed to fill element proofs: %w", err)
			} else if len(proof) != 1 {
				panic("expected exactly one proof") // should never happen
			}
			ele.StateElement.MerkleProof = proof[0]
		}
		return nil
	})
	if errors.Is(err, sql.ErrNoRows) {
		err = wallet.ErrNotFound
	}
	return
}

// BigFileElementSpentEvent returns the event that spent a BigFile UTXO.
func (s *Store) BigFileElementSpentEvent(id types.BigFileOutputID) (ev wallet.Event, spent bool, err error) {
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

// SiafundElementSpentEvent returns the event that spent a Siafund UTXO.
func (s *Store) SiafundElementSpentEvent(id types.SiafundOutputID) (ev wallet.Event, spent bool, err error) {
	err = s.transaction(func(tx *txn) error {
		const query = `SELECT spent_event_id FROM siafund_elements WHERE id=$1`

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
