package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"go.thebigfile.com/core/types"
	"go.thebigfile.com/walletd/v2/wallet"
)

// CheckAddresses returns true if any of the addresses have been seen on the
// blockchain. This is a quick way to scan wallets for lookaheads.
//
// If the index mode is not full, this function will only return true if
// an address is registered with a wallet.
func (s *Store) CheckAddresses(addresses []types.Address) (known bool, err error) {
	err = s.transaction(func(tx *txn) error {
		stmt, err := tx.Prepare(`SELECT true FROM bigfile_addresses WHERE bigfile_address=$1`)
		if err != nil {
			return fmt.Errorf("failed to prepare statement: %w", err)
		}
		defer stmt.Close()

		for _, addr := range addresses {
			if err := stmt.QueryRow(encode(addr)).Scan(&known); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					continue
				}
				return fmt.Errorf("failed to query address: %w", err)
			}
			if known {
				return nil
			}
		}
		return nil
	})
	return
}

// AddressBalance returns the aggregate balance of the addresses.
func (s *Store) AddressBalance(address ...types.Address) (balance wallet.Balance, err error) {
	if len(address) == 0 {
		return wallet.Balance{}, nil // no addresses, no balance
	}
	err = s.transaction(func(tx *txn) error {
		const query = `SELECT bigfile_balance, immature_bigfile_balance, bigfund_balance FROM bigfile_addresses WHERE bigfile_address=$1`
		stmt, err := tx.Prepare(query)
		if err != nil {
			return fmt.Errorf("failed to prepare statement: %w", err)
		}
		defer stmt.Close()

		for _, addr := range address {
			var bigfiles, immatureBigfiles types.Currency
			var bigfunds uint64

			if err := stmt.QueryRow(encode(addr)).Scan(decode(&bigfiles), decode(&immatureBigfiles), &bigfunds); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("failed to query address %q: %w", addr, err)
			}
			balance.Bigfiles = balance.Bigfiles.Add(bigfiles)
			balance.ImmatureBigfiles = balance.ImmatureBigfiles.Add(immatureBigfiles)
			balance.Bigfunds += bigfunds
		}
		return nil
	})
	return
}

// BatchAddressEvents returns the events for a batch of addresses.
func (s *Store) BatchAddressEvents(addresses []types.Address, offset, limit int) (events []wallet.Event, err error) {
	if len(addresses) == 0 {
		return nil, nil // no addresses, no events
	}
	err = s.transaction(func(tx *txn) error {
		dbIDs, err := s.getAddressesEvents(tx, addresses, offset, limit)
		if err != nil {
			return fmt.Errorf("failed to get events for addresses: %w", err)
		}
		if len(dbIDs) == 0 {
			return nil // no events found
		}

		events, err = getEventsByID(tx, dbIDs)
		if err != nil {
			return fmt.Errorf("failed to get events by ID: %w", err)
		}

		addressMap := make(map[types.Address]bool)
		for _, addr := range addresses {
			addressMap[addr] = true
		}
		for i := range events {
			seen := make(map[types.Address]bool)
			switch ev := events[i].Data.(type) {
			case wallet.EventV1Transaction:
				for _, bigi := range ev.Transaction.BigfileInputs {
					addr := bigi.UnlockConditions.UnlockHash()
					if addressMap[addr] && !seen[addr] {
						seen[addr] = true
						events[i].Relevant = append(events[i].Relevant, addr)
					}
				}
				for _, bigo := range ev.Transaction.BigfileOutputs {
					if addressMap[bigo.Address] && !seen[bigo.Address] {
						seen[bigo.Address] = true
						events[i].Relevant = append(events[i].Relevant, bigo.Address)
					}
				}
				for _, bfi := range ev.Transaction.BigfundInputs {
					addr := bfi.UnlockConditions.UnlockHash()
					if addressMap[addr] && !seen[addr] {
						seen[addr] = true
						events[i].Relevant = append(events[i].Relevant, addr)
					}
				}
				for _, bfo := range ev.Transaction.BigfundOutputs {
					if addressMap[bfo.Address] && !seen[bfo.Address] {
						seen[bfo.Address] = true
						events[i].Relevant = append(events[i].Relevant, bfo.Address)
					}
				}
			case wallet.EventV2Transaction:
				for _, bigi := range ev.BigfileInputs {
					if addressMap[bigi.Parent.BigfileOutput.Address] && !seen[bigi.Parent.BigfileOutput.Address] {
						seen[bigi.Parent.BigfileOutput.Address] = true
						events[i].Relevant = append(events[i].Relevant, bigi.Parent.BigfileOutput.Address)
					}
				}
				for _, bigo := range ev.BigfileOutputs {
					if addressMap[bigo.Address] && !seen[bigo.Address] {
						seen[bigo.Address] = true
						events[i].Relevant = append(events[i].Relevant, bigo.Address)
					}
				}
				for _, bfi := range ev.BigfundInputs {
					if addressMap[bfi.Parent.BigfundOutput.Address] && !seen[bfi.Parent.BigfundOutput.Address] {
						seen[bfi.Parent.BigfundOutput.Address] = true
						events[i].Relevant = append(events[i].Relevant, bfi.Parent.BigfundOutput.Address)
					}
				}
				for _, bfo := range ev.BigfundOutputs {
					if addressMap[bfo.Address] && !seen[bfo.Address] {
						seen[bfo.Address] = true
						events[i].Relevant = append(events[i].Relevant, bfo.Address)
					}
				}
			case wallet.EventPayout:
				events[i].Relevant = append(events[i].Relevant, ev.BigfileElement.BigfileOutput.Address)
			}
		}
		return nil
	})
	return
}

// BatchAddressBigfileOutputs returns the unspent bigfile outputs for an address.
func (s *Store) BatchAddressBigfileOutputs(addresses []types.Address, offset, limit int) (bigfiles []wallet.UnspentBigfileElement, basis types.ChainIndex, err error) {
	err = s.transaction(func(tx *txn) error {
		basis, err = getScanBasis(tx)
		if err != nil {
			return fmt.Errorf("failed to get basis: %w", err)
		}

		query := `SELECT se.id, se.bigfile_value, se.merkle_proof, se.leaf_index, se.maturity_height, sa.bigfile_address, ci.height 
		FROM bigfile_elements se
		INNER JOIN chain_indices ci ON (se.chain_index_id = ci.id)
		INNER JOIN bigfile_addresses sa ON (se.address_id = sa.id)
		WHERE sa.bigfile_address IN (` + queryPlaceHolders(len(addresses)) + `) AND se.maturity_height <= ? AND se.spent_index_id IS NULL
		LIMIT ? OFFSET ?`

		rows, err := tx.Query(query, append(encodeSlice(addresses), basis.Height, limit, offset)...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			bigfile, err := scanUnspentBigfileElement(rows, basis.Height)
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

// BatchAddressBigfundOutputs returns the unspent bigfund outputs for an address.
func (s *Store) BatchAddressBigfundOutputs(addresses []types.Address, offset, limit int) (bigfunds []wallet.UnspentBigfundElement, basis types.ChainIndex, err error) {
	err = s.transaction(func(tx *txn) error {
		basis, err = getScanBasis(tx)
		if err != nil {
			return fmt.Errorf("failed to get basis: %w", err)
		}

		query := `SELECT se.id, se.leaf_index, se.merkle_proof, se.bigfund_value, se.claim_start, sa.bigfile_address, ci.height
		FROM bigfund_elements se
		INNER JOIN chain_indices ci ON (se.chain_index_id = ci.id)
		INNER JOIN bigfile_addresses sa ON (se.address_id = sa.id)
		WHERE sa.bigfile_address IN(` + queryPlaceHolders(len(addresses)) + `) AND se.spent_index_id IS NULL
		ORDER BY se.id DESC
		LIMIT ? OFFSET ?`

		rows, err := tx.Query(query, append(encodeSlice(addresses), limit, offset)...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			bigfund, err := scanUnspentBigfundElement(rows, basis.Height)
			if err != nil {
				return fmt.Errorf("failed to scan bigfund element: %w", err)
			}
			bigfunds = append(bigfunds, bigfund)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		// retrieve the merkle proofs for the bigfund elements
		if s.indexMode == wallet.IndexModeFull {
			indices := make([]uint64, len(bigfunds))
			for i, se := range bigfunds {
				indices[i] = se.StateElement.LeafIndex
			}
			proofs, err := fillElementProofs(tx, indices)
			if err != nil {
				return fmt.Errorf("failed to fill element proofs: %w", err)
			}
			for i, proof := range proofs {
				bigfunds[i].StateElement.MerkleProof = proof
			}
		}
		return nil
	})
	return
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

// AddressBigfileOutputs returns the unspent bigfile outputs for an address.
func (s *Store) AddressBigfileOutputs(address types.Address, tpoolSpent []types.BigfileOutputID, offset, limit int) (bigfiles []wallet.UnspentBigfileElement, basis types.ChainIndex, err error) {
	err = s.transaction(func(tx *txn) error {
		basis, err = getScanBasis(tx)
		if err != nil {
			return fmt.Errorf("failed to get basis: %w", err)
		}

		query := `SELECT se.id, se.bigfile_value, se.merkle_proof, se.leaf_index, se.maturity_height, sa.bigfile_address, ci.height 
		FROM bigfile_elements se
		INNER JOIN chain_indices ci ON (se.chain_index_id = ci.id)
		INNER JOIN bigfile_addresses sa ON (se.address_id = sa.id)
		WHERE sa.bigfile_address = ? AND se.maturity_height <= ? AND se.spent_index_id IS NULL`

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
			bigfile, err := scanUnspentBigfileElement(rows, basis.Height)
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

// AddressBigfundOutputs returns the unspent bigfund outputs for an address.
func (s *Store) AddressBigfundOutputs(address types.Address, tpoolSpent []types.BigfundOutputID, offset, limit int) (bigfunds []wallet.UnspentBigfundElement, basis types.ChainIndex, err error) {
	err = s.transaction(func(tx *txn) error {
		basis, err = getScanBasis(tx)
		if err != nil {
			return fmt.Errorf("failed to get basis: %w", err)
		}

		query := `SELECT se.id, se.leaf_index, se.merkle_proof, se.bigfund_value, se.claim_start, sa.bigfile_address, ci.height
		FROM bigfund_elements se
		INNER JOIN chain_indices ci ON (se.chain_index_id = ci.id)
		INNER JOIN bigfile_addresses sa ON (se.address_id = sa.id)
		WHERE sa.bigfile_address=? AND se.spent_index_id IS NULL`

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
			bigfund, err := scanUnspentBigfundElement(rows, basis.Height)
			if err != nil {
				return fmt.Errorf("failed to scan bigfund element: %w", err)
			}
			bigfunds = append(bigfunds, bigfund)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		// retrieve the merkle proofs for the bigfund elements
		if s.indexMode == wallet.IndexModeFull {
			indices := make([]uint64, len(bigfunds))
			for i, se := range bigfunds {
				indices[i] = se.StateElement.LeafIndex
			}
			proofs, err := fillElementProofs(tx, indices)
			if err != nil {
				return fmt.Errorf("failed to fill element proofs: %w", err)
			}
			for i, proof := range proofs {
				bigfunds[i].StateElement.MerkleProof = proof
			}
		}
		return nil
	})
	return
}

// AnnotateV1Events annotates a list of unconfirmed transactions with
// relevant addresses and bigfile/bigfund elements.
func (s *Store) AnnotateV1Events(index types.ChainIndex, timestamp time.Time, v1 []types.Transaction) (annotated []wallet.Event, err error) {
	err = s.transaction(func(tx *txn) error {
		bigfileElementStmt, err := tx.Prepare(`SELECT se.id, se.bigfile_value, se.merkle_proof, se.leaf_index, se.maturity_height, sa.bigfile_address
		FROM bigfile_elements se
		INNER JOIN bigfile_addresses sa ON (se.address_id = sa.id)
		WHERE se.id=$1`)
		if err != nil {
			return fmt.Errorf("failed to prepare bigfile statement: %w", err)
		}
		defer bigfileElementStmt.Close()

		bigfileElementCache := make(map[types.BigfileOutputID]types.BigfileElement)
		fetchBigfileElement := func(id types.BigfileOutputID) (types.BigfileElement, error) {
			if se, ok := bigfileElementCache[id]; ok {
				return se, nil
			}

			se, err := scanBigfileElement(bigfileElementStmt.QueryRow(encode(id)))
			if err != nil {
				return types.BigfileElement{}, fmt.Errorf("failed to fetch bigfile element: %w", err)
			}
			bigfileElementCache[id] = se
			return se, nil
		}

		bigfundElementStmt, err := tx.Prepare(`SELECT se.id, se.leaf_index, se.merkle_proof, se.bigfund_value, se.claim_start, sa.bigfile_address
		FROM bigfund_elements se
		INNER JOIN bigfile_addresses sa ON (se.address_id = sa.id)
		WHERE se.id=$1`)
		if err != nil {
			return fmt.Errorf("failed to prepare bigfund statement: %w", err)
		}
		defer bigfundElementStmt.Close()

		bigfundElementCache := make(map[types.BigfundOutputID]types.BigfundElement)
		fetchBigfundElement := func(id types.BigfundOutputID) (types.BigfundElement, error) {
			if se, ok := bigfundElementCache[id]; ok {
				return se, nil
			}

			se, err := scanBigfundElement(bigfundElementStmt.QueryRow(encode(id)))
			if err != nil {
				return types.BigfundElement{}, fmt.Errorf("failed to fetch bigfund element: %w", err)
			}
			bigfundElementCache[id] = se
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

			for _, input := range txn.BigfileInputs {
				// fetch the bigfile element
				bige, err := fetchBigfileElement(input.ParentID)
				if errors.Is(err, sql.ErrNoRows) {
					continue // ignore elements that are not found
				} else if err != nil {
					return fmt.Errorf("failed to fetch bigfile element %q: %w", input.ParentID, err)
				}
				ev.SpentBigfileElements = append(ev.SpentBigfileElements, bige)
				relevant = true
			}

			for i, output := range txn.BigfileOutputs {
				bige := types.BigfileElement{
					ID: txn.BigfileOutputID(i),
					StateElement: types.StateElement{
						LeafIndex: types.UnassignedLeafIndex,
					},
					BigfileOutput: output,
				}
				bigfileElementCache[bige.ID] = bige
				relevant = true
			}

			for _, input := range txn.BigfundInputs {
				// fetch the bigfund element
				bfe, err := fetchBigfundElement(input.ParentID)
				if errors.Is(err, sql.ErrNoRows) {
					continue // ignore elements that are not found
				} else if err != nil {
					return fmt.Errorf("failed to fetch bigfund element %q: %w", input.ParentID, err)
				}
				ev.SpentBigfundElements = append(ev.SpentBigfundElements, bfe)
				relevant = true
			}

			for i, output := range txn.BigfundOutputs {
				bfe := types.BigfundElement{
					ID: txn.BigfundOutputID(i),
					StateElement: types.StateElement{
						LeafIndex: types.UnassignedLeafIndex,
					},
					BigfundOutput: output,
				}
				bigfundElementCache[bfe.ID] = bfe
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

func getAddressEvents(tx *txn, address types.Address, offset, limit int) (eventIDs []int64, err error) {
	const query = `SELECT DISTINCT ea.event_id
FROM event_addresses ea
INNER JOIN bigfile_addresses sa ON ea.address_id = sa.id
WHERE sa.bigfile_address = $1
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

func (s *Store) getAddressesEvents(tx *txn, addresses []types.Address, offset, limit int) (eventIDs []int64, err error) {
	if len(addresses) == 0 {
		return nil, nil // no addresses, no events
	}

	query := `SELECT DISTINCT ea.event_id
FROM event_addresses ea
INNER JOIN bigfile_addresses sa ON ea.address_id = sa.id
WHERE sa.bigfile_address IN (` + queryPlaceHolders(len(addresses)) + `)
ORDER BY ea.event_maturity_height DESC, ea.event_id DESC
LIMIT ? OFFSET ?;`

	params := make([]any, 0, len(addresses)+2)
	for _, addr := range addresses {
		params = append(params, encode(addr))
	}
	params = append(params, limit, offset)
	rows, err := tx.Query(query, params...)
	if err != nil {
		return nil, fmt.Errorf("failed to query address events: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan event ID: %w", err)
		}
		eventIDs = append(eventIDs, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over rows: %w", err)
	}
	return eventIDs, nil
}
