package wallet

import (
	"time"

	"go.thebigfile.com/core/types"
)

// CheckAddresses returns true if any of the addresses have been seen on the
// blockchain. This is a quick way to scan wallets for lookaheads.
func (m *Manager) CheckAddresses(address []types.Address) (bool, error) {
	return m.store.CheckAddresses(address)
}

// AddressBalance returns the balance of a single address.
func (m *Manager) AddressBalance(addresses ...types.Address) (balance Balance, err error) {
	return m.store.AddressBalance(addresses...)
}

// AddressBigfileOutputs returns the unspent bigfile outputs for an address.
func (m *Manager) AddressBigfileOutputs(address types.Address, usePool bool, offset, limit int) ([]UnspentBigfileElement, types.ChainIndex, error) {
	if !usePool {
		return m.store.AddressBigfileOutputs(address, nil, offset, limit)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	spent := m.poolAddressSCSpent[address]
	var created []UnspentBigfileElement
	for _, bige := range m.poolBIGCreated {
		if bige.BigfileOutput.Address != address {
			continue
		}

		bige.StateElement = bige.StateElement.Copy()
		created = append(created, UnspentBigfileElement{
			BigfileElement: bige,
		})
	}

	outputs, basis, err := m.store.AddressBigfileOutputs(address, spent, offset, limit)
	if err != nil {
		return nil, types.ChainIndex{}, err
	} else if len(outputs) == limit {
		return outputs, basis, nil
	}
	return append(outputs, created...), basis, nil
}

// AddressBigfundOutputs returns the unspent bigfund outputs for an address.
func (m *Manager) AddressBigfundOutputs(address types.Address, usePool bool, offset, limit int) ([]UnspentBigfundElement, types.ChainIndex, error) {
	if !usePool {
		return m.store.AddressBigfundOutputs(address, nil, offset, limit)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	spent := m.poolAddressSFSpent[address]
	var created []UnspentBigfundElement
	for _, bfe := range m.poolBFCreated {
		if bfe.BigfundOutput.Address != address {
			continue
		}
		bfe.StateElement = bfe.StateElement.Copy()
		created = append(created, UnspentBigfundElement{
			BigfundElement: bfe,
		})
	}

	outputs, basis, err := m.store.AddressBigfundOutputs(address, spent, offset, limit)
	if err != nil {
		return nil, types.ChainIndex{}, err
	} else if len(outputs) == limit {
		return outputs, basis, nil
	}
	return append(outputs, created...), basis, nil
}

// AddressEvents returns the events of a single address.
func (m *Manager) AddressEvents(address types.Address, offset, limit int) (events []Event, err error) {
	return m.store.AddressEvents(address, offset, limit)
}

// BatchAddressEvents returns the events for a batch of addresses.
func (m *Manager) BatchAddressEvents(addresses []types.Address, offset, limit int) ([]Event, error) {
	if len(addresses) == 0 {
		return nil, nil // no addresses, no events
	}
	return m.store.BatchAddressEvents(addresses, offset, limit)
}

// BatchAddressBigfileOutputs returns the unspent bigfile outputs for a batch of addresses.
func (m *Manager) BatchAddressBigfileOutputs(addresses []types.Address, offset, limit int) ([]UnspentBigfileElement, types.ChainIndex, error) {
	if len(addresses) == 0 {
		return nil, types.ChainIndex{}, nil // no addresses, no outputs
	}
	return m.store.BatchAddressBigfileOutputs(addresses, offset, limit)
}

// BatchAddressBigfundOutputs returns the unspent bigfund outputs for a batch of addresses.
func (m *Manager) BatchAddressBigfundOutputs(addresses []types.Address, offset, limit int) ([]UnspentBigfundElement, types.ChainIndex, error) {
	if len(addresses) == 0 {
		return nil, types.ChainIndex{}, nil // no addresses, no outputs
	}
	return m.store.BatchAddressBigfundOutputs(addresses, offset, limit)
}

// AddressUnconfirmedEvents returns the unconfirmed events for a single address.
func (m *Manager) AddressUnconfirmedEvents(address types.Address) ([]Event, error) {
	index := m.chain.Tip()
	index.Height++
	index.ID = types.BlockID{}
	timestamp := time.Now()

	v1, v2 := m.chain.PoolTransactions(), m.chain.V2PoolTransactions()

	relevantV1Txn := func(txn types.Transaction) bool {
		for _, output := range txn.BigfileOutputs {
			if output.Address == address {
				return true
			}
		}
		for _, input := range txn.BigfileInputs {
			if input.UnlockConditions.UnlockHash() == address {
				return true
			}
		}
		for _, output := range txn.BigfundOutputs {
			if output.Address == address {
				return true
			}
		}
		for _, input := range txn.BigfundInputs {
			if input.UnlockConditions.UnlockHash() == address {
				return true
			}
		}
		return false
	}

	relevantV1 := v1[:0]
	for _, txn := range v1 {
		if !relevantV1Txn(txn) {
			continue
		}
		relevantV1 = append(relevantV1, txn)
	}

	events, err := m.store.AnnotateV1Events(index, timestamp, relevantV1)
	if err != nil {
		return nil, err
	}

	for i := range events {
		events[i].Relevant = []types.Address{address}
	}

	relevantV2Txn := func(txn types.V2Transaction) bool {
		for _, output := range txn.BigfileOutputs {
			if output.Address == address {
				return true
			}
		}
		for _, input := range txn.BigfileInputs {
			if input.Parent.BigfileOutput.Address == address {
				return true
			}
		}
		for _, output := range txn.BigfundOutputs {
			if output.Address == address {
				return true
			}
		}
		for _, input := range txn.BigfundInputs {
			if input.Parent.BigfundOutput.Address == address {
				return true
			}
		}
		return false
	}

	// Annotate v2 transactions.
	for _, txn := range v2 {
		if !relevantV2Txn(txn) {
			continue
		}

		events = append(events, Event{
			ID:             types.Hash256(txn.ID()),
			Index:          index,
			Timestamp:      timestamp,
			MaturityHeight: index.Height,
			Type:           EventTypeV2Transaction,
			Data:           EventV2Transaction(txn),
			Relevant:       []types.Address{address},
		})
	}
	return events, nil
}
