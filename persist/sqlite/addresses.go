package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"go.thebigfile.com/core/types"
	"go.thebigfile.com/walletd/v2/wallet"
)

// AddressBalance returns the balance of a single address.
func (s *Store) AddressBalance(address types.Address) (balance wallet.Balance, err error) {
	err = s.transaction(func(tx *txn) error {
		const query = `SELECT bigfile_balance, immature_bigfile_balance, siafund_balance FROM sia_addresses WHERE sia_address=$1`
		err := tx.QueryRow(query, encode(address)).Scan(decode(&balance.BigFiles), decode(&balance.ImmatureBigFiles), &balance.Siafunds)
		if errors.Is(err, sql.ErrNoRows) {
			balance = wallet.Balance{}
			return nil
		}
		return err
	})
	return
}

func getAddressEvents(tx *txn, address types.Address, offset, limit int) (eventIDs []int64, err error) {
	const query = `SELECT DISTINCT ea.event_id
FROM event_addresses ea
INNER JOIN sia_addresses sa ON ea.address_id = sa.id
WHERE sa.sia_address = $1
ORDER BY ea.event_maturity_height DESC, ea.event_id DESC
LIMIT $2 OFFSET $3;`

	rows, err := tx.Query(query, encode(address), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		eventIDs = append(eventIDs, id)
	}
	return eventIDs, rows.Err()
}

// AddressEvents returns the events of a single address.
func (s *Store) AddressEvents(address types.Address, offset, limit int) (events []wallet.Event, err error) {
	err = s.transaction(func(tx *txn) error {
		dbIDs, err := getAddressEvents(tx, address, offset, limit)
		if err != nil {
			return err
		}

		events, err = getEventsByID(tx, dbIDs)
		if err != nil {
			return fmt.Errorf("failed to get events by ID: %w", err)
		}

		for i := range events {
			events[i].Relevant = []types.Address{address}
		}
		return nil
	})
	return
}

// AddressBigFileOutputs returns the unspent bigfile outputs for an address.
func (s *Store) AddressBigFileOutputs(address types.Address, tpoolSpent []types.BigFileOutputID, offset, limit int) (bigfiles []wallet.UnspentBigFileElement, basis types.ChainIndex, err error) {
	err = s.transaction(func(tx *txn) error {
		basis, err = getScanBasis(tx)
		if err != nil {
			return fmt.Errorf("failed to get basis: %w", err)
		}

		query := `SELECT se.id, se.bigfile_value, se.merkle_proof, se.leaf_index, se.maturity_height, sa.sia_address, ci.height 
		FROM bigfile_elements se
		INNER JOIN chain_indices ci ON (se.chain_index_id = ci.id)
		INNER JOIN sia_addresses sa ON (se.address_id = sa.id)
		WHERE sa.sia_address = ? AND se.maturity_height <= ? AND se.spent_index_id IS NULL`

		params := []any{encode(address), basis.Height}
		if len(tpoolSpent) > 0 {
			query += ` AND se.ID NOT IN (` + queryPlaceHolders(len(tpoolSpent)) + `)`
			params = append(params, encodeSlice(tpoolSpent)...)
		}

		query += ` ORDER BY se.maturity_height DESC, se.id DESC
		LIMIT ? OFFSET ?`

		params = append(params, limit, offset)

		rows, err := tx.Query(query, params...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			bigfile, err := scanUnspentBigFileElement(rows, basis.Height)
			if err != nil {
				return fmt.Errorf("failed to scan bigfile element: %w", err)
			}

			bigfiles = append(bigfiles, bigfile)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		// retrieve the merkle proofs for the bigfile elements
		if s.indexMode == wallet.IndexModeFull {
			indices := make([]uint64, len(bigfiles))
			for i, se := range bigfiles {
				indices[i] = se.StateElement.LeafIndex
			}
			proofs, err := fillElementProofs(tx, indices)
			if err != nil {
				return fmt.Errorf("failed to fill element proofs: %w", err)
			}
			for i, proof := range proofs {
				bigfiles[i].StateElement.MerkleProof = proof
			}
		}
		return nil
	})
	return
}

// AddressSiafundOutputs returns the unspent siafund outputs for an address.
func (s *Store) AddressSiafundOutputs(address types.Address, tpoolSpent []types.SiafundOutputID, offset, limit int) (siafunds []wallet.UnspentSiafundElement, basis types.ChainIndex, err error) {
	err = s.transaction(func(tx *txn) error {
		basis, err = getScanBasis(tx)
		if err != nil {
			return fmt.Errorf("failed to get basis: %w", err)
		}

		query := `SELECT se.id, se.leaf_index, se.merkle_proof, se.siafund_value, se.claim_start, sa.sia_address, ci.height
		FROM siafund_elements se
		INNER JOIN chain_indices ci ON (se.chain_index_id = ci.id)
		INNER JOIN sia_addresses sa ON (se.address_id = sa.id)
		WHERE sa.sia_address=? AND se.spent_index_id IS NULL`

		params := []any{encode(address)}

		if len(tpoolSpent) > 0 {
			query += ` AND se.id NOT IN (` + queryPlaceHolders(len(tpoolSpent)) + `)`
			params = append(params, encodeSlice(tpoolSpent)...)
		}

		query += ` ORDER BY se.id DESC
		LIMIT ? OFFSET ?`

		params = append(params, limit, offset)

		rows, err := tx.Query(query, params...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			siafund, err := scanUnspentSiafundElement(rows, basis.Height)
			if err != nil {
				return fmt.Errorf("failed to scan siafund element: %w", err)
			}
			siafunds = append(siafunds, siafund)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		// retrieve the merkle proofs for the siafund elements
		if s.indexMode == wallet.IndexModeFull {
			indices := make([]uint64, len(siafunds))
			for i, se := range siafunds {
				indices[i] = se.StateElement.LeafIndex
			}
			proofs, err := fillElementProofs(tx, indices)
			if err != nil {
				return fmt.Errorf("failed to fill element proofs: %w", err)
			}
			for i, proof := range proofs {
				siafunds[i].StateElement.MerkleProof = proof
			}
		}
		return nil
	})
	return
}

// AnnotateV1Events annotates a list of unconfirmed transactions with
// relevant addresses and bigfile/siafund elements.
func (s *Store) AnnotateV1Events(index types.ChainIndex, timestamp time.Time, v1 []types.Transaction) (annotated []wallet.Event, err error) {
	err = s.transaction(func(tx *txn) error {
		bigfileElementStmt, err := tx.Prepare(`SELECT se.id, se.bigfile_value, se.merkle_proof, se.leaf_index, se.maturity_height, sa.sia_address
		FROM bigfile_elements se
		INNER JOIN sia_addresses sa ON (se.address_id = sa.id)
		WHERE se.id=$1`)
		if err != nil {
			return fmt.Errorf("failed to prepare bigfile statement: %w", err)
		}
		defer bigfileElementStmt.Close()

		bigfileElementCache := make(map[types.BigFileOutputID]types.BigFileElement)
		fetchBigFileElement := func(id types.BigFileOutputID) (types.BigFileElement, error) {
			if se, ok := bigfileElementCache[id]; ok {
				return se, nil
			}

			se, err := scanBigFileElement(bigfileElementStmt.QueryRow(encode(id)))
			if err != nil {
				return types.BigFileElement{}, fmt.Errorf("failed to fetch bigfile element: %w", err)
			}
			bigfileElementCache[id] = se
			return se, nil
		}

		siafundElementStmt, err := tx.Prepare(`SELECT se.id, se.leaf_index, se.merkle_proof, se.siafund_value, se.claim_start, sa.sia_address
		FROM siafund_elements se
		INNER JOIN sia_addresses sa ON (se.address_id = sa.id)
		WHERE se.id=$1`)
		if err != nil {
			return fmt.Errorf("failed to prepare siafund statement: %w", err)
		}
		defer siafundElementStmt.Close()

		siafundElementCache := make(map[types.SiafundOutputID]types.SiafundElement)
		fetchSiafundElement := func(id types.SiafundOutputID) (types.SiafundElement, error) {
			if se, ok := siafundElementCache[id]; ok {
				return se, nil
			}

			se, err := scanSiafundElement(siafundElementStmt.QueryRow(encode(id)))
			if err != nil {
				return types.SiafundElement{}, fmt.Errorf("failed to fetch siafund element: %w", err)
			}
			siafundElementCache[id] = se
			return se, nil
		}

		addEvent := func(id types.Hash256, data wallet.EventData) {
			annotated = append(annotated, wallet.Event{
				ID:             id,
				Index:          index,
				Timestamp:      timestamp,
				MaturityHeight: index.Height,
				Type:           wallet.EventTypeV1Transaction,
				Data:           data,
			})
		}

		for _, txn := range v1 {
			var relevant bool
			ev := wallet.EventV1Transaction{
				Transaction: txn,
			}

			for _, input := range txn.BigFileInputs {
				// fetch the bigfile element
				sce, err := fetchBigFileElement(input.ParentID)
				if errors.Is(err, sql.ErrNoRows) {
					continue // ignore elements that are not found
				} else if err != nil {
					return fmt.Errorf("failed to fetch bigfile element %q: %w", input.ParentID, err)
				}
				ev.SpentBigFileElements = append(ev.SpentBigFileElements, sce)
				relevant = true
			}

			for i, output := range txn.BigFileOutputs {
				sce := types.BigFileElement{
					ID: txn.BigFileOutputID(i),
					StateElement: types.StateElement{
						LeafIndex: types.UnassignedLeafIndex,
					},
					BigFileOutput: output,
				}
				bigfileElementCache[sce.ID] = sce
				relevant = true
			}

			for _, input := range txn.SiafundInputs {
				// fetch the siafund element
				sfe, err := fetchSiafundElement(input.ParentID)
				if errors.Is(err, sql.ErrNoRows) {
					continue // ignore elements that are not found
				} else if err != nil {
					return fmt.Errorf("failed to fetch siafund element %q: %w", input.ParentID, err)
				}
				ev.SpentSiafundElements = append(ev.SpentSiafundElements, sfe)
				relevant = true
			}

			for i, output := range txn.SiafundOutputs {
				sfe := types.SiafundElement{
					ID: txn.SiafundOutputID(i),
					StateElement: types.StateElement{
						LeafIndex: types.UnassignedLeafIndex,
					},
					SiafundOutput: output,
				}
				siafundElementCache[sfe.ID] = sfe
				relevant = true
			}

			if !relevant {
				continue
			}

			addEvent(types.Hash256(txn.ID()), ev)
		}
		return nil
	})
	return
}
