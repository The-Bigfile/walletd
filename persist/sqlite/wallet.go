package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"math/bits"
	"time"

	"go.thebigfile.com/core/types"
	"go.thebigfile.com/walletd/v2/wallet"
)

func (s *Store) getWalletEventRelevantAddresses(tx *txn, id wallet.ID, eventIDs []int64) (map[int64][]types.Address, error) {
	stmt, err := tx.Prepare(`SELECT sa.bigfile_address
FROM event_addresses ea
INNER JOIN bigfile_addresses sa ON (ea.address_id = sa.id)
INNER JOIN wallet_addresses wa ON (ea.address_id = wa.address_id)
WHERE wa.wallet_id=? AND ea.event_id=?`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	relevant := func(walletID wallet.ID, eventID int64) (addresses []types.Address, err error) {
		rows, err := stmt.Query(walletID, eventID)
		if err != nil {
			return nil, fmt.Errorf("failed to query relevant addresses: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var address types.Address
			if err := rows.Scan(decode(&address)); err != nil {
				return nil, fmt.Errorf("failed to scan relevant address: %w", err)
			}
			addresses = append(addresses, address)
		}
		return addresses, rows.Err()
	}

	relevantAddresses := make(map[int64][]types.Address)
	for _, eventID := range eventIDs {
		addresses, err := relevant(id, eventID)
		if err != nil {
			return nil, err
		}
		relevantAddresses[eventID] = addresses
	}
	return relevantAddresses, nil
}

// WalletEvents returns the events relevant to a wallet, sorted by height descending.
func (s *Store) WalletEvents(id wallet.ID, offset, limit int) (events []wallet.Event, err error) {
	err = s.transaction(func(tx *txn) error {
		dbIDs, err := getWalletEvents(tx, id, offset, limit)
		if err != nil {
			return fmt.Errorf("failed to get wallet events: %w", err)
		}

		events, err = getEventsByID(tx, dbIDs)
		if err != nil {
			return fmt.Errorf("failed to get events by ID: %w", err)
		}

		eventRelevantAddresses, err := s.getWalletEventRelevantAddresses(tx, id, dbIDs)
		if err != nil {
			return fmt.Errorf("failed to get relevant addresses: %w", err)
		}

		for i := range events {
			events[i].Relevant = eventRelevantAddresses[dbIDs[i]]
		}
		return nil
	})
	return
}

// AddWallet adds a wallet to the database.
func (s *Store) AddWallet(w wallet.Wallet) (wallet.Wallet, error) {
	w.DateCreated = time.Now().Truncate(time.Second)
	w.LastUpdated = time.Now().Truncate(time.Second)

	err := s.transaction(func(tx *txn) error {
		const query = `INSERT INTO wallets (friendly_name, description, date_created, last_updated, extra_data) VALUES ($1, $2, $3, $4, $5) RETURNING id`
		return tx.QueryRow(query, w.Name, w.Description, encode(w.DateCreated), encode(w.LastUpdated), w.Metadata).Scan(&w.ID)
	})
	return w, err
}

// UpdateWallet updates a wallet in the database.
func (s *Store) UpdateWallet(w wallet.Wallet) (wallet.Wallet, error) {
	w.LastUpdated = time.Now()
	err := s.transaction(func(tx *txn) error {
		var dummyID int64
		const query = `UPDATE wallets SET friendly_name=$1, description=$2, last_updated=$3, extra_data=$4 WHERE id=$5 RETURNING id, date_created, last_updated`
		err := tx.QueryRow(query, w.Name, w.Description, encode(w.LastUpdated), w.Metadata, w.ID).Scan(&dummyID, decode(&w.DateCreated), decode(&w.LastUpdated))
		if errors.Is(err, sql.ErrNoRows) {
			return wallet.ErrNotFound
		}
		return err
	})
	return w, err
}

// DeleteWallet deletes a wallet from the database. This does not stop tracking
// addresses that were previously associated with the wallet.
func (s *Store) DeleteWallet(id wallet.ID) error {
	return s.transaction(func(tx *txn) error {
		_, err := tx.Exec(`DELETE FROM wallet_addresses WHERE wallet_id=$1`, id)
		if err != nil {
			return fmt.Errorf("failed to delete wallet addresses: %w", err)
		}

		var dummyID int64
		err = tx.QueryRow(`DELETE FROM wallets WHERE id=$1 RETURNING id`, id).Scan(&dummyID)
		if errors.Is(err, sql.ErrNoRows) {
			return wallet.ErrNotFound
		}
		return err
	})
}

// Wallets returns a map of wallet names to wallet extra data.
func (s *Store) Wallets() (wallets []wallet.Wallet, err error) {
	err = s.transaction(func(tx *txn) error {
		const query = `SELECT id, friendly_name, description, date_created, last_updated, extra_data FROM wallets`

		rows, err := tx.Query(query)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var w wallet.Wallet
			if err := rows.Scan(&w.ID, &w.Name, &w.Description, decode(&w.DateCreated), decode(&w.LastUpdated), (*[]byte)(&w.Metadata)); err != nil {
				return fmt.Errorf("failed to scan wallet: %w", err)
			}
			wallets = append(wallets, w)
		}
		return rows.Err()
	})
	return
}

// AddWalletAddresses adds the given addresses to a wallet.
func (s *Store) AddWalletAddresses(id wallet.ID, walletAddresses ...wallet.Address) error {
	return s.transaction(func(tx *txn) error {
		if err := walletExists(tx, id); err != nil {
			return err
		} else if len(walletAddresses) == 0 {
			return errors.New("no addresses to add")
		}

		addresses := make([]types.Address, 0, len(walletAddresses))
		for _, wa := range walletAddresses {
			addresses = append(addresses, wa.Address)
		}

		addressDBIDs, err := insertAddress(tx, addresses...)
		if err != nil {
			return fmt.Errorf("failed to insert addresses: %w", err)
		}

		stmt, err := tx.Prepare(`INSERT INTO wallet_addresses (wallet_id, address_id, description, spend_policy, extra_data) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (wallet_id, address_id) DO UPDATE set description=EXCLUDED.description, spend_policy=EXCLUDED.spend_policy, extra_data=EXCLUDED.extra_data`)
		if err != nil {
			return fmt.Errorf("failed to prepare wallet address insert statement: %w", err)
		}
		defer stmt.Close()

		for i, wa := range walletAddresses {
			addressDBID := addressDBIDs[i]

			var encodedPolicy any
			if wa.SpendPolicy != nil {
				encodedPolicy = encode(*wa.SpendPolicy)
			}

			_, err = stmt.Exec(id, addressDBID, wa.Description, encodedPolicy, wa.Metadata)
			if err != nil {
				return fmt.Errorf("failed to insert wallet address %q: %w", wa.Address, err)
			}
		}
		return nil
	})
}

// RemoveWalletAddress removes an address from a wallet. This does not stop tracking
// the address.
func (s *Store) RemoveWalletAddress(id wallet.ID, address types.Address) error {
	return s.transaction(func(tx *txn) error {
		const query = `DELETE FROM wallet_addresses WHERE wallet_id=$1 AND address_id=(SELECT id FROM bigfile_addresses WHERE bigfile_address=$2) RETURNING address_id`
		var dummyID int64
		err := tx.QueryRow(query, id, encode(address)).Scan(&dummyID)
		if errors.Is(err, sql.ErrNoRows) {
			return wallet.ErrNotFound
		}
		return err
	})
}

// WalletAddress returns an address registered to the wallet.
func (s *Store) WalletAddress(id wallet.ID, address types.Address) (addr wallet.Address, err error) {
	err = s.transaction(func(tx *txn) error {
		if err := walletExists(tx, id); err != nil {
			return err
		}

		const query = `SELECT sa.bigfile_address, wa.description, wa.spend_policy, wa.extra_data
FROM wallet_addresses wa
INNER JOIN bigfile_addresses sa ON (sa.id = wa.address_id)
WHERE wa.wallet_id=$1 AND sa.bigfile_address=$2`

		addr, err = scanWalletAddress(tx.QueryRow(query, id, encode(address)))
		return err
	})
	return
}

// WalletAddresses returns a slice of addresses registered to the wallet.
func (s *Store) WalletAddresses(id wallet.ID) (addresses []wallet.Address, err error) {
	err = s.transaction(func(tx *txn) error {
		if err := walletExists(tx, id); err != nil {
			return err
		}

		const query = `SELECT sa.bigfile_address, wa.description, wa.spend_policy, wa.extra_data
FROM wallet_addresses wa
INNER JOIN bigfile_addresses sa ON (sa.id = wa.address_id)
WHERE wa.wallet_id=$1`

		rows, err := tx.Query(query, id)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			addr, err := scanWalletAddress(rows)
			if err != nil {
				return fmt.Errorf("failed to scan address: %w", err)
			}
			addresses = append(addresses, addr)
		}
		return rows.Err()
	})
	return
}

// WalletBigfileOutputs returns the unspent bigfile outputs for a wallet.
func (s *Store) WalletBigfileOutputs(id wallet.ID, offset, limit int) (bigfiles []wallet.UnspentBigfileElement, basis types.ChainIndex, err error) {
	err = s.transaction(func(tx *txn) error {
		if err := walletExists(tx, id); err != nil {
			return err
		}

		basis, err = getScanBasis(tx)
		if err != nil {
			return fmt.Errorf("failed to get basis: %w", err)
		}

		const query = `SELECT se.id, se.bigfile_value, se.merkle_proof, se.leaf_index, se.maturity_height, sa.bigfile_address, ci.height 
		FROM bigfile_elements se
		INNER JOIN chain_indices ci ON (se.chain_index_id = ci.id)
		INNER JOIN bigfile_addresses sa ON (se.address_id = sa.id)
		WHERE se.spent_index_id IS NULL AND se.maturity_height <= $1 AND se.address_id IN (SELECT address_id FROM wallet_addresses WHERE wallet_id=$2)
		LIMIT $3 OFFSET $4`

		rows, err := tx.Query(query, basis.Height, id, limit, offset)
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

// WalletBigfundOutputs returns the unspent bigfund outputs for a wallet.
func (s *Store) WalletBigfundOutputs(id wallet.ID, offset, limit int) (bigfunds []wallet.UnspentBigfundElement, basis types.ChainIndex, err error) {
	err = s.transaction(func(tx *txn) error {
		if err := walletExists(tx, id); err != nil {
			return err
		}

		basis, err = getScanBasis(tx)
		if err != nil {
			return fmt.Errorf("failed to get basis: %w", err)
		}

		const query = `SELECT se.id, se.leaf_index, se.merkle_proof, se.bigfund_value, se.claim_start, sa.bigfile_address, ci.height
		FROM bigfund_elements se
		INNER JOIN chain_indices ci ON (se.chain_index_id = ci.id)
		INNER JOIN bigfile_addresses sa ON (se.address_id = sa.id)
		WHERE se.spent_index_id IS NULL AND se.address_id IN (SELECT address_id FROM wallet_addresses WHERE wallet_id=$1)
		LIMIT $2 OFFSET $3`

		rows, err := tx.Query(query, id, limit, offset)
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

		// retrieve the merkle proofs for the bigfile elements
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

// WalletBalance returns the total balance of a wallet.
func (s *Store) WalletBalance(id wallet.ID) (balance wallet.Balance, err error) {
	err = s.transaction(func(tx *txn) error {
		if err := walletExists(tx, id); err != nil {
			return err
		}

		const query = `SELECT bigfile_balance, immature_bigfile_balance, bigfund_balance FROM bigfile_addresses sa
		INNER JOIN wallet_addresses wa ON (sa.id = wa.address_id)
		WHERE wa.wallet_id=$1`

		rows, err := tx.Query(query, id)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var addressSC types.Currency
			var addressISC types.Currency
			var addressSF uint64

			if err := rows.Scan(decode(&addressSC), decode(&addressISC), &addressSF); err != nil {
				return fmt.Errorf("failed to scan address balance: %w", err)
			}
			balance.Bigfiles = balance.Bigfiles.Add(addressSC)
			balance.ImmatureBigfiles = balance.ImmatureBigfiles.Add(addressISC)
			balance.Bigfunds += addressSF
		}
		return rows.Err()
	})
	return
}

// WalletUnconfirmedEvents annotates a list of unconfirmed transactions with
// relevant addresses and bigfile/bigfund elements.
func (s *Store) WalletUnconfirmedEvents(id wallet.ID, index types.ChainIndex, timestamp time.Time, v1 []types.Transaction, v2 []types.V2Transaction) (annotated []wallet.Event, err error) {
	err = s.transaction(func(tx *txn) error {
		if err := walletExists(tx, id); err != nil {
			return err
		}

		addrStmt, err := tx.Prepare(`SELECT sa.id FROM bigfile_addresses sa
	INNER JOIN wallet_addresses wa ON (sa.id = wa.address_id)
	WHERE wa.wallet_id=$1 AND sa.bigfile_address=$2 LIMIT 1`)
		if err != nil {
			return fmt.Errorf("failed to prepare address statement: %w", err)
		}
		defer addrStmt.Close()

		// note: this would be more performant for small wallets to load all
		// addresses into memory. However, for larger wallets (> 10K addresses),
		// this is time consuming. Instead, the database is queried for each
		// address. Monitor performance and consider changing this in the
		// future. From a memory perspective, it would be fine to lazy load all
		// addresses into memory.
		checkedAddresses := make(map[types.Address]bool)
		ownsAddress := func(address types.Address) bool {
			if relevant, ok := checkedAddresses[address]; ok {
				return relevant
			}

			var dbID int64
			err := addrStmt.QueryRow(id, encode(address)).Scan(&dbID)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				panic(err) // database error
			}
			relevant := err == nil
			checkedAddresses[address] = relevant
			return relevant
		}

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

		addEvent := func(id types.Hash256, eventType string, data wallet.EventData, relevant []types.Address) {
			annotated = append(annotated, wallet.Event{
				ID:             id,
				Index:          index,
				Timestamp:      timestamp,
				MaturityHeight: index.Height + 1,
				Type:           eventType,
				Data:           data,
				Relevant:       relevant,
			})
		}

		for _, txn := range v1 {
			var relevant []types.Address
			seen := make(map[types.Address]bool)
			ev := wallet.EventV1Transaction{
				Transaction: txn,
			}

			for _, input := range txn.BigfileInputs {
				address := input.UnlockConditions.UnlockHash()
				if !ownsAddress(address) {
					continue
				}

				if !seen[address] {
					seen[address] = true
					relevant = append(relevant, address)
				}

				// fetch the bigfile element
				bige, err := fetchBigfileElement(input.ParentID)
				if err != nil {
					return fmt.Errorf("failed to fetch bigfile element %q: %w", input.ParentID, err)
				}
				ev.SpentBigfileElements = append(ev.SpentBigfileElements, bige)
			}

			for i, output := range txn.BigfileOutputs {
				if !ownsAddress(output.Address) {
					continue
				}

				if !seen[output.Address] {
					seen[output.Address] = true
					relevant = append(relevant, output.Address)
				}

				bige := types.BigfileElement{
					ID: txn.BigfileOutputID(i),
					StateElement: types.StateElement{
						LeafIndex: types.UnassignedLeafIndex,
					},
					BigfileOutput: output,
				}
				bigfileElementCache[bige.ID] = bige
			}

			for _, input := range txn.BigfundInputs {
				address := input.UnlockConditions.UnlockHash()
				if !ownsAddress(address) {
					continue
				}

				if !seen[address] {
					seen[address] = true
					relevant = append(relevant, address)
				}

				// fetch the bigfund element
				bfe, err := fetchBigfundElement(input.ParentID)
				if err != nil {
					return fmt.Errorf("failed to fetch bigfund element %q: %w", input.ParentID, err)
				}
				ev.SpentBigfundElements = append(ev.SpentBigfundElements, bfe)
			}

			for i, output := range txn.BigfundOutputs {
				if !ownsAddress(output.Address) {
					continue
				}

				if !seen[output.Address] {
					seen[output.Address] = true
					relevant = append(relevant, output.Address)
				}

				bfe := types.BigfundElement{
					ID: txn.BigfundOutputID(i),
					StateElement: types.StateElement{
						LeafIndex: types.UnassignedLeafIndex,
					},
					BigfundOutput: output,
				}
				bigfundElementCache[bfe.ID] = bfe
			}

			if len(relevant) == 0 {
				continue
			}
			addEvent(types.Hash256(txn.ID()), wallet.EventTypeV1Transaction, ev, relevant)
		}

		// only need to check if the address is relevant for v2 transactions
		// the inputs contain the necessary metadata for calculating value
		for _, txn := range v2 {
			var relevant []types.Address
			seen := make(map[types.Address]bool)

			for _, bigi := range txn.BigfileInputs {
				if !ownsAddress(bigi.Parent.BigfileOutput.Address) || seen[bigi.Parent.BigfileOutput.Address] {
					continue
				}
				seen[bigi.Parent.BigfileOutput.Address] = true
				relevant = append(relevant, bigi.Parent.BigfileOutput.Address)
			}

			for _, bigo := range txn.BigfileOutputs {
				if !ownsAddress(bigo.Address) || seen[bigo.Address] {
					continue
				}
				seen[bigo.Address] = true
				relevant = append(relevant, bigo.Address)
			}

			for _, bfi := range txn.BigfundInputs {
				if !ownsAddress(bfi.Parent.BigfundOutput.Address) || seen[bfi.Parent.BigfundOutput.Address] {
					continue
				}
				seen[bfi.Parent.BigfundOutput.Address] = true
				relevant = append(relevant, bfi.Parent.BigfundOutput.Address)
			}

			for _, bfo := range txn.BigfundOutputs {
				if !ownsAddress(bfo.Address) || seen[bfo.Address] {
					continue
				}
				seen[bfo.Address] = true
				relevant = append(relevant, bfo.Address)
			}

			if len(relevant) == 0 {
				continue
			}

			addEvent(types.Hash256(txn.ID()), wallet.EventTypeV2Transaction, wallet.EventV2Transaction(txn), relevant)
		}
		return nil
	})
	return
}

func scanUnspentBigfileElement(s scanner, basisHeight uint64) (se wallet.UnspentBigfileElement, err error) {
	var confirmationHeight uint64
	err = s.Scan(decode(&se.ID), decode(&se.BigfileOutput.Value), decode(&se.StateElement.MerkleProof), &se.StateElement.LeafIndex, &se.MaturityHeight, decode(&se.BigfileOutput.Address), &confirmationHeight)
	if confirmationHeight <= basisHeight {
		se.Confirmations = 1 + basisHeight - confirmationHeight
	}
	return
}

func scanUnspentBigfundElement(s scanner, basisHeight uint64) (se wallet.UnspentBigfundElement, err error) {
	var confirmationHeight uint64
	err = s.Scan(decode(&se.ID), &se.StateElement.LeafIndex, decode(&se.StateElement.MerkleProof), &se.BigfundOutput.Value, decode(&se.ClaimStart), decode(&se.BigfundOutput.Address), &confirmationHeight)
	if confirmationHeight <= basisHeight {
		se.Confirmations = 1 + basisHeight - confirmationHeight
	}
	return
}

func scanBigfileElement(s scanner) (se types.BigfileElement, err error) {
	err = s.Scan(decode(&se.ID), decode(&se.BigfileOutput.Value), decode(&se.StateElement.MerkleProof), &se.StateElement.LeafIndex, &se.MaturityHeight, decode(&se.BigfileOutput.Address))
	return
}

func scanBigfundElement(s scanner) (se types.BigfundElement, err error) {
	err = s.Scan(decode(&se.ID), &se.StateElement.LeafIndex, decode(&se.StateElement.MerkleProof), &se.BigfundOutput.Value, decode(&se.ClaimStart), decode(&se.BigfundOutput.Address))
	return
}

func insertAddress(tx *txn, addrs ...types.Address) (ids []int64, err error) {
	const query = `INSERT INTO bigfile_addresses (bigfile_address, bigfile_balance, immature_bigfile_balance, bigfund_balance)
VALUES ($1, $2, $3, 0) ON CONFLICT (bigfile_address) DO UPDATE SET bigfile_address=EXCLUDED.bigfile_address
RETURNING id`

	if len(addrs) == 0 {
		return nil, errors.New("no addresses to insert")
	}

	stmt, err := tx.Prepare(query)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare address insert statement: %w", err)
	}
	defer stmt.Close()
	for _, addr := range addrs {
		var id int64
		if err := stmt.QueryRow(encode(addr), encode(types.ZeroCurrency), encode(types.ZeroCurrency)).Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to insert address %q: %w", addr, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func scanWalletAddress(s scanner) (wallet.Address, error) {
	var address wallet.Address
	var decodedPolicy any
	if err := s.Scan(decode(&address.Address), &address.Description, &decodedPolicy, (*[]byte)(&address.Metadata)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return wallet.Address{}, wallet.ErrNotFound
		}
		return wallet.Address{}, fmt.Errorf("failed to scan address: %w", err)
	}

	if decodedPolicy != nil {
		switch v := decodedPolicy.(type) {
		case []byte:
			dec := types.NewBufDecoder(v)
			address.SpendPolicy = new(types.SpendPolicy)
			address.SpendPolicy.DecodeFrom(dec)
			if err := dec.Err(); err != nil {
				return wallet.Address{}, fmt.Errorf("failed to decode spend policy: %w", err)
			}
		default:
			return wallet.Address{}, fmt.Errorf("unexpected spend policy type: %T", decodedPolicy)
		}
	}
	return address, nil
}

func getScanBasis(tx *txn) (index types.ChainIndex, err error) {
	err = tx.QueryRow(`SELECT last_indexed_id, last_indexed_height FROM global_settings`).Scan(decode(&index.ID), &index.Height)
	return
}

func fillElementProofs(tx *txn, indices []uint64) (proofs [][]types.Hash256, _ error) {
	if len(indices) == 0 {
		return nil, nil
	}

	var numLeaves uint64
	if err := tx.QueryRow(`SELECT element_num_leaves FROM global_settings LIMIT 1`).Scan(&numLeaves); err != nil {
		return nil, fmt.Errorf("failed to query state tree leaves: %w", err)
	}

	stmt, err := tx.Prepare(`SELECT value FROM state_tree WHERE row=? AND column=?`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	data := make(map[uint64]map[uint64]types.Hash256)
	for _, leafIndex := range indices {
		proof := make([]types.Hash256, bits.Len64(leafIndex^numLeaves)-1)
		for j := range proof {
			row, col := uint64(j), (leafIndex>>j)^1

			// check if the hash is already in the cache
			if h, ok := data[row][col]; ok {
				proof[j] = h
				continue
			}

			// query the hash from the database
			if err := stmt.QueryRow(row, col).Scan(decode(&proof[j])); err != nil {
				return nil, fmt.Errorf("failed to query state element (%d,%d): %w", row, col, err)
			}

			// cache the hash
			if _, ok := data[row]; !ok {
				data[row] = make(map[uint64]types.Hash256)
			}
			data[row][col] = proof[j]
		}
		proofs = append(proofs, proof)
	}
	return
}

func getWalletEvents(tx *txn, id wallet.ID, offset, limit int) (eventIDs []int64, err error) {
	const eventsQuery = `SELECT DISTINCT ea.event_id
FROM event_addresses ea
INNER JOIN bigfile_addresses sa ON ea.address_id = sa.id
INNER JOIN wallet_addresses wa ON sa.id = wa.address_id
WHERE wa.wallet_id = $1
ORDER BY ea.event_maturity_height DESC, ea.event_id DESC
LIMIT $2 OFFSET $3;`

	rows, err := tx.Query(eventsQuery, id, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var eventID int64
		if err := rows.Scan(&eventID); err != nil {
			return nil, fmt.Errorf("failed to scan event ID: %w", err)
		}
		eventIDs = append(eventIDs, eventID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return
}

func walletExists(tx *txn, id wallet.ID) error {
	const query = `SELECT 1 FROM wallets WHERE id=$1`
	var dummy int
	err := tx.QueryRow(query, id).Scan(&dummy)
	if errors.Is(err, sql.ErrNoRows) {
		return wallet.ErrNotFound
	}
	return err
}

// OverwriteElementProofs overwrites the element proofs for the given transactions.
func (s *Store) OverwriteElementProofs(txns []types.V2Transaction) (basis types.ChainIndex, updated []types.V2Transaction, err error) {
	err = s.transaction(func(tx *txn) error {
		basis, err = getScanBasis(tx)
		if err != nil {
			return fmt.Errorf("failed to get basis: %w", err)
		}

		for _, txn := range txns {
			txn = txn.DeepCopy()
			for i, bigi := range txn.BigfileInputs {
				ele, err := getBigfileElement(tx, bigi.Parent.ID, s.indexMode)
				if errors.Is(err, sql.ErrNoRows) {
					continue
				} else if err != nil {
					return fmt.Errorf("failed to get bigfile element: %w", err)
				}
				txn.BigfileInputs[i].Parent = ele
			}
			for i, bfi := range txn.BigfundInputs {
				ele, err := getBigfundElement(tx, bfi.Parent.ID, s.indexMode)
				if errors.Is(err, sql.ErrNoRows) {
					continue
				} else if err != nil {
					return fmt.Errorf("failed to get bigfund element: %w", err)
				}
				txn.BigfundInputs[i].Parent = ele
			}
			updated = append(updated, txn)
		}
		return nil
	})
	return
}
