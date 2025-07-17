package wallet

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"go.thebigfile.com/core/consensus"
	"go.thebigfile.com/core/types"
	"go.thebigfile.com/coreutils/chain"
	"go.thebigfile.com/walletd/v2/internal/threadgroup"
	"go.uber.org/zap"
	"golang.org/x/exp/constraints"
)

const maxReorgPeriod = 3 * time.Hour

// IndexMode represents the index mode of the wallet manager. The index mode
// determines how the wallet manager stores the consensus state.
//
// IndexModePersonal - The wallet manager scans the blockchain starting at
// genesis. Only state from addresses that are registered with a
// wallet will be stored. If an address is added to a wallet after the
// scan completes, the manager will need to rescan.
//
// IndexModeFull - The wallet manager scans the blockchain starting at genesis
// and stores the state of all addresses.
//
// IndexModeNone - The wallet manager does not scan the blockchain. This is
// useful for multiple nodes sharing the same database. None should only be used
// when connecting to a database that is in "Full" mode.
const (
	IndexModePersonal IndexMode = iota
	IndexModeFull
	IndexModeNone
)

const defaultSyncBatchSize = 1

var (
	// ErrInsufficientFunds is returned when there are not enough funds to
	// fund a transaction.
	ErrInsufficientFunds = errors.New("insufficient funds")
	// ErrAlreadyReserved is returned when trying to reserve an output that is
	// already reserved.
	ErrAlreadyReserved = errors.New("output already reserved")
	// ErrNotSyncing is returned when the consensus has not
	// had a block change within the last 3 hours.
	ErrNotSyncing = errors.New("not syncing")
	// ErrNotSynced is returned when the wallet has not
	ErrNotSynced = errors.New("not synced")
)

type (
	// An IndexMode determines the chain state that the wallet manager stores.
	IndexMode uint8

	// A ChainManager manages the consensus state
	ChainManager interface {
		PoolTransactions() []types.Transaction
		V2PoolTransactions() []types.V2Transaction

		Tip() types.ChainIndex
		TipState() consensus.State
		BestIndex(height uint64) (types.ChainIndex, bool)

		OnReorg(func(types.ChainIndex)) (cancel func())
		OnPoolChange(func()) (cancel func())
		UpdatesSince(index types.ChainIndex, max int) (rus []chain.RevertUpdate, aus []chain.ApplyUpdate, err error)
	}

	// A Store is a persistent store of wallet data.
	Store interface {
		UpdateChainState(reverted []chain.RevertUpdate, applied []chain.ApplyUpdate) error
		ResetChainState() error

		WalletUnconfirmedEvents(id ID, index types.ChainIndex, timestamp time.Time, v1 []types.Transaction, v2 []types.V2Transaction) (annotated []Event, err error)
		WalletEvents(walletID ID, offset, limit int) ([]Event, error)
		AddWallet(Wallet) (Wallet, error)
		UpdateWallet(Wallet) (Wallet, error)
		DeleteWallet(walletID ID) error
		WalletBalance(walletID ID) (Balance, error)
		WalletAddress(ID, types.Address) (Address, error)
		WalletBigfileOutputs(walletID ID, offset, limit int) ([]UnspentBigfileElement, types.ChainIndex, error)
		WalletBigfundOutputs(walletID ID, offset, limit int) ([]UnspentBigfundElement, types.ChainIndex, error)
		WalletAddresses(walletID ID) ([]Address, error)
		Wallets() ([]Wallet, error)

		AddWalletAddresses(walletID ID, addresses ...Address) error
		RemoveWalletAddress(walletID ID, address types.Address) error

		AddressBalance(address ...types.Address) (balance Balance, err error)
		AddressEvents(address types.Address, offset, limit int) (events []Event, err error)
		AddressBigfileOutputs(address types.Address, tpoolSpent []types.BigfileOutputID, offset, limit int) ([]UnspentBigfileElement, types.ChainIndex, error)
		AddressBigfundOutputs(address types.Address, tpoolSpent []types.BigfundOutputID, offset, limit int) ([]UnspentBigfundElement, types.ChainIndex, error)

		BatchAddressEvents(addresses []types.Address, offset, limit int) ([]Event, error)
		BatchAddressBigfileOutputs(addresses []types.Address, offset, limit int) ([]UnspentBigfileElement, types.ChainIndex, error)
		BatchAddressBigfundOutputs(addresses []types.Address, offset, limit int) ([]UnspentBigfundElement, types.ChainIndex, error)

		// CheckAddresses returns true if any of the addresses have been seen on the
		// blockchain. This is a quick way to scan wallets for lookaheads.
		//
		// If index mode is full, this function returns true if any
		// address has been seen on chain.
		//
		// In personal index mode, this function returns true only
		// if the address is registered to a wallet.
		CheckAddresses([]types.Address) (bool, error)
		OverwriteElementProofs(txns []types.V2Transaction) (basis types.ChainIndex, updated []types.V2Transaction, err error)

		Events(eventIDs []types.Hash256) ([]Event, error)
		AnnotateV1Events(index types.ChainIndex, timestamp time.Time, v1 []types.Transaction) (annotated []Event, err error)

		BigfileElement(types.BigfileOutputID) (types.BigfileElement, error)
		BigfundElement(types.BigfundOutputID) (types.BigfundElement, error)
		// BigfileElementSpentEvent returns the event of a spent bigfile element.
		// If the element is not spent, the return value will be (Event{}, false, nil).
		// If the element is not found, the error will be ErrNotFound. An element
		// is only tracked for 144 blocks after it is spent.
		BigfileElementSpentEvent(types.BigfileOutputID) (Event, bool, error)
		// BigfundElementSpentEvent returns the event of a spent bigfund element.
		// If the element is not spent, the second return value will be (Event{}, false, nil).
		// If the element is not found, the error will be ErrNotFound. An element
		// is only tracked for 144 blocks after it is spent.
		BigfundElementSpentEvent(types.BigfundOutputID) (Event, bool, error)

		SetIndexMode(IndexMode) error
		LastCommittedIndex() (types.ChainIndex, error)
	}

	// A Manager manages wallets.
	Manager struct {
		indexMode     IndexMode
		syncBatchSize int
		lockDuration  time.Duration

		chain ChainManager
		store Store
		log   *zap.Logger
		tg    *threadgroup.ThreadGroup

		mu   sync.Mutex // protects the fields below
		used map[types.Hash256]time.Time
		// tracks the state of utxos in the transaction pool
		// this local state is used to remove a race between
		// the wallet indexing and the chain manager
		poolBIGCreated     map[types.BigfileOutputID]types.BigfileElement
		poolBFCreated      map[types.BigfundOutputID]types.BigfundElement
		poolBIGSpent       map[types.BigfileOutputID]bool
		poolBFSpent        map[types.BigfundOutputID]bool
		poolAddressSCSpent map[types.Address][]types.BigfileOutputID
		poolAddressSFSpent map[types.Address][]types.BigfundOutputID
	}
)

// String returns the string representation of the index mode.
func (i IndexMode) String() string {
	switch i {
	case IndexModePersonal:
		return "personal"
	case IndexModeFull:
		return "full"
	case IndexModeNone:
		return "none"
	default:
		return "unknown"
	}
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (i *IndexMode) UnmarshalText(buf []byte) error {
	switch string(buf) {
	case "personal":
		*i = IndexModePersonal
	case "full":
		*i = IndexModeFull
	case "none":
		*i = IndexModeNone
	default:
		return fmt.Errorf("unknown index mode %q", buf)
	}
	return nil
}

// MarshalText implements the encoding.TextMarshaler interface.
func (i IndexMode) MarshalText() ([]byte, error) {
	return []byte(i.String()), nil
}

// lockUTXOs locks the given UTXOs for the duration of the lock duration.
// The lock duration is used to prevent double spending when building transactions.
// It is expected that the caller holds the manager's lock.
func (m *Manager) lockUTXOs(ids ...types.Hash256) {
	ts := time.Now().Add(m.lockDuration)
	for _, id := range ids {
		m.used[id] = ts
	}
}

// utxosLocked returns an error if any of the given UTXOs are locked.
// It is expected that the caller holds the manager's lock.
func (m *Manager) utxosLocked(ids ...types.Hash256) error {
	for _, id := range ids {
		if m.used[id].After(time.Now()) {
			return fmt.Errorf("failed to lock output %q: %w", id, ErrAlreadyReserved)
		}
	}
	return nil
}

// Health checks if the wallet manager is healthy. It checks if the
// last block in the chain manager is recent enough and if the last indexed block
// is not too far behind the chain manager. If either of these checks fail, an
// error is returned.
func (m *Manager) Health() error {
	cs := m.chain.TipState()
	lastBlockTimestamp := cs.PrevTimestamps[0]
	if time.Since(lastBlockTimestamp) > maxReorgPeriod {
		return fmt.Errorf("last block timestamp %s is too old: %w", lastBlockTimestamp, ErrNotSyncing)
	}

	maxSyncedDelta := uint64(maxReorgPeriod / cs.Network.BlockInterval)
	indexedTip, err := m.store.LastCommittedIndex()
	if err != nil {
		return fmt.Errorf("failed to get tip: %w", err)
	} else if n := delta(indexedTip.Height, cs.Index.Height); n > maxSyncedDelta {
		return fmt.Errorf("last indexed block %q is too far behind tip %q: %w", indexedTip, cs.Index, ErrNotSynced)
	}
	return nil
}

// SyncPool forces a sync of the transaction pool for testing
// purposes.
func (m *Manager) SyncPool() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resetPool()
}

// Tip returns the last scanned chain index of the manager.
func (m *Manager) Tip() (types.ChainIndex, error) {
	return m.store.LastCommittedIndex()
}

// AddWallet adds the given wallet.
func (m *Manager) AddWallet(w Wallet) (Wallet, error) {
	return m.store.AddWallet(w)
}

// UpdateWallet updates the given wallet.
func (m *Manager) UpdateWallet(w Wallet) (Wallet, error) {
	return m.store.UpdateWallet(w)
}

// DeleteWallet deletes the given wallet.
func (m *Manager) DeleteWallet(walletID ID) error {
	return m.store.DeleteWallet(walletID)
}

// Wallets returns the wallets of the wallet manager.
func (m *Manager) Wallets() ([]Wallet, error) {
	return m.store.Wallets()
}

// AddAddresses adds the addresses to the given wallet.
func (m *Manager) AddAddresses(walletID ID, addrs ...Address) error {
	return m.store.AddWalletAddresses(walletID, addrs...)
}

// RemoveAddress removes the given address from the given wallet.
func (m *Manager) RemoveAddress(walletID ID, addr types.Address) error {
	return m.store.RemoveWalletAddress(walletID, addr)
}

// Addresses returns the addresses of the given wallet.
func (m *Manager) Addresses(walletID ID) ([]Address, error) {
	return m.store.WalletAddresses(walletID)
}

// WalletEvents returns the events of the given wallet.
func (m *Manager) WalletEvents(walletID ID, offset, limit int) ([]Event, error) {
	return m.store.WalletEvents(walletID, offset, limit)
}

// UnspentBigfileOutputs returns a paginated list of matured bigfile outputs
// relevant to the wallet
func (m *Manager) UnspentBigfileOutputs(walletID ID, offset, limit int) ([]UnspentBigfileElement, types.ChainIndex, error) {
	return m.store.WalletBigfileOutputs(walletID, offset, limit)
}

// UnspentBigfundOutputs returns a paginated list of bigfund outputs relevant to
// the wallet
func (m *Manager) UnspentBigfundOutputs(walletID ID, offset, limit int) ([]UnspentBigfundElement, types.ChainIndex, error) {
	return m.store.WalletBigfundOutputs(walletID, offset, limit)
}

// WalletUnconfirmedEvents returns the unconfirmed events of the given wallet.
func (m *Manager) WalletUnconfirmedEvents(walletID ID) ([]Event, error) {
	index := m.chain.Tip()
	index.Height++
	index.ID = types.BlockID{}
	return m.store.WalletUnconfirmedEvents(walletID, index, time.Now(), m.chain.PoolTransactions(), m.chain.V2PoolTransactions())
}

// WalletBalance returns the balance of the given wallet.
func (m *Manager) WalletBalance(walletID ID) (Balance, error) {
	return m.store.WalletBalance(walletID)
}

// Events returns the events with the given IDs.
func (m *Manager) Events(eventIDs []types.Hash256) ([]Event, error) {
	return m.store.Events(eventIDs)
}

// UnconfirmedEvents returns all unconfirmed events in the transaction pool.
func (m *Manager) UnconfirmedEvents() ([]Event, error) {
	v1, v2 := m.chain.PoolTransactions(), m.chain.V2PoolTransactions()

	unconfirmedIndex := m.chain.Tip()
	unconfirmedIndex.Height++
	unconfirmedIndex.ID = types.BlockID{}
	timestamp := time.Now()

	events, err := m.store.AnnotateV1Events(unconfirmedIndex, timestamp, v1)
	if err != nil {
		return nil, err
	}

	for _, txn := range v2 {
		events = append(events, Event{
			ID:        types.Hash256(txn.ID()),
			Index:     unconfirmedIndex,
			Timestamp: timestamp,
			Type:      EventTypeV2Transaction,
			Data:      EventV2Transaction(txn),
		})
	}
	return events, nil
}

// Reserve reserves the given ids for the given duration.
func (m *Manager) Reserve(ids []types.Hash256) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// check if any of the ids are already reserved
	if err := m.utxosLocked(ids...); err != nil {
		return err
	}
	m.lockUTXOs(ids...)
	return nil
}

// Release releases the given ids.
func (m *Manager) Release(ids []types.Hash256) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, id := range ids {
		delete(m.used, id)
	}
}

// WalletAddress returns an address from the wallet.
func (m *Manager) WalletAddress(id ID, addr types.Address) (Address, error) {
	return m.store.WalletAddress(id, addr)
}

// SelectBigfileElements selects bigfile elements from the wallet that sum to
// at least the given amount. Returns the elements, the element basis, and the
// change amount.
func (m *Manager) SelectBigfileElements(walletID ID, amount types.Currency, useUnconfirmed bool) ([]UnspentBigfileElement, types.ChainIndex, types.Currency, error) {
	// sanity check that the wallet exists
	if _, err := m.WalletBalance(walletID); err != nil {
		return nil, types.ChainIndex{}, types.ZeroCurrency, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	knownAddresses := make(map[types.Address]bool)
	relevantAddr := func(addr types.Address) (bool, error) {
		if exists, ok := knownAddresses[addr]; ok {
			return exists, nil
		}
		_, err := m.store.WalletAddress(walletID, addr)
		if errors.Is(err, ErrNotFound) {
			knownAddresses[addr] = false
			return false, nil
		} else if err != nil {
			return false, err
		}
		knownAddresses[addr] = true
		return true, nil
	}

	var ephemeral []types.BigfileElement
	for _, bige := range m.poolBIGCreated {
		exists, err := relevantAddr(bige.BigfileOutput.Address)
		if err != nil {
			return nil, types.ChainIndex{}, types.ZeroCurrency, fmt.Errorf("failed to check if address %q is relevant: %w", bige.BigfileOutput.Address, err)
		} else if !exists {
			continue
		}
		ephemeral = append(ephemeral, bige)
	}
	inPool := m.poolBIGSpent

	var inputSum types.Currency
	var selected []UnspentBigfileElement
	var utxoIDs []types.Hash256
	var basis types.ChainIndex
	const utxoBatchSize = 100
top:
	for i := 0; ; i += utxoBatchSize {
		var utxos []UnspentBigfileElement
		var err error
		// extra large wallets may need to paginate through utxos
		// to find enough to cover the amount
		utxos, basis, err = m.store.WalletBigfileOutputs(walletID, i, utxoBatchSize)
		if err != nil {
			return nil, types.ChainIndex{}, types.ZeroCurrency, fmt.Errorf("failed to get bigfile elements: %w", err)
		} else if len(utxos) == 0 {
			break top
		}

		for _, bige := range utxos {
			if inPool[bige.ID] || m.utxosLocked(types.Hash256(bige.ID)) != nil {
				continue
			}

			selected = append(selected, bige)
			utxoIDs = append(utxoIDs, types.Hash256(bige.ID))
			inputSum = inputSum.Add(bige.BigfileOutput.Value)
			if inputSum.Cmp(amount) >= 0 {
				break top
			}
		}
	}

	if inputSum.Cmp(amount) < 0 {
		if !useUnconfirmed {
			return nil, types.ChainIndex{}, types.ZeroCurrency, ErrInsufficientFunds
		}

		for _, bige := range ephemeral {
			if inPool[bige.ID] || m.utxosLocked(types.Hash256(bige.ID)) != nil {
				continue
			}

			selected = append(selected, UnspentBigfileElement{
				BigfileElement: bige,
				Confirmations:  0,
			})
			inputSum = inputSum.Add(bige.BigfileOutput.Value)
			if inputSum.Cmp(amount) >= 0 {
				break
			}
		}
	}

	if inputSum.Cmp(amount) < 0 {
		return nil, types.ChainIndex{}, types.ZeroCurrency, ErrInsufficientFunds
	}
	m.lockUTXOs(utxoIDs...)
	return selected, basis, inputSum.Sub(amount), nil
}

// SelectBigfundElements selects bigfund elements from the wallet that sum to
// at least the given amount. Returns the elements, the element basis, and the
// change amount.
func (m *Manager) SelectBigfundElements(walletID ID, amount uint64) ([]UnspentBigfundElement, types.ChainIndex, uint64, error) {
	// sanity check that the wallet exists
	if _, err := m.WalletBalance(walletID); err != nil {
		return nil, types.ChainIndex{}, 0, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if amount == 0 {
		return nil, m.chain.Tip(), 0, nil
	}

	var inputSum uint64
	var selected []UnspentBigfundElement
	var utxoIDs []types.Hash256
	var basis types.ChainIndex
	const utxoBatchSize = 100
top:
	for i := 0; ; i += utxoBatchSize {
		var utxos []UnspentBigfundElement
		var err error

		utxos, basis, err = m.store.WalletBigfundOutputs(walletID, i, utxoBatchSize)
		if err != nil {
			return nil, types.ChainIndex{}, 0, fmt.Errorf("failed to get bigfund elements: %w", err)
		} else if len(utxos) == 0 {
			break top
		}

		for _, bfe := range utxos {
			if m.poolBFSpent[bfe.ID] || m.utxosLocked(types.Hash256(bfe.ID)) != nil {
				continue
			}

			selected = append(selected, bfe)
			utxoIDs = append(utxoIDs, types.Hash256(bfe.ID))
			inputSum += bfe.BigfundOutput.Value
			if inputSum >= amount {
				break top
			}
		}
	}

	if inputSum < amount {
		return nil, types.ChainIndex{}, 0, ErrInsufficientFunds
	}

	m.lockUTXOs(utxoIDs...)
	return selected, basis, inputSum - amount, nil
}

// OverwriteElementProofs overwrites the proofs of the given transactions.
func (m *Manager) OverwriteElementProofs(txns []types.V2Transaction) (types.ChainIndex, []types.V2Transaction, error) {
	return m.store.OverwriteElementProofs(txns)
}

// Scan rescans the chain starting from the given index. The scan will complete
// when the chain manager reaches the current tip or the context is canceled.
func (m *Manager) Scan(ctx context.Context, index types.ChainIndex) error {
	if m.indexMode != IndexModePersonal {
		return fmt.Errorf("scans are disabled in index mode %s", m.indexMode)
	}

	ctx, cancel, err := m.tg.AddWithContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	m.mu.Lock()
	defer m.mu.Unlock()
	return syncStore(ctx, m.store, m.chain, index, m.syncBatchSize)
}

// IndexMode returns the index mode of the wallet manager.
func (m *Manager) IndexMode() IndexMode {
	return m.indexMode
}

// BigfileElement returns the unspent bigfile element with the given id.
func (m *Manager) BigfileElement(id types.BigfileOutputID) (types.BigfileElement, error) {
	return m.store.BigfileElement(id)
}

// BigfundElement returns the unspent bigfund element with the given id.
func (m *Manager) BigfundElement(id types.BigfundOutputID) (types.BigfundElement, error) {
	return m.store.BigfundElement(id)
}

// BigfileElementSpentEvent returns the event of a spent bigfile element.
// If the element is not spent, the return value will be (Event{}, false, nil).
// If the element is not found, the error will be ErrNotFound. An element
// is only tracked for 144 blocks after it is spent.
func (m *Manager) BigfileElementSpentEvent(id types.BigfileOutputID) (Event, bool, error) {
	return m.store.BigfileElementSpentEvent(id)
}

// BigfundElementSpentEvent returns the event of a spent bigfund element.
// If the element is not spent, the second return value will be (Event{}, false, nil).
// If the element is not found, the error will be ErrNotFound. An element
// is only tracked for 144 blocks after it is spent.
func (m *Manager) BigfundElementSpentEvent(id types.BigfundOutputID) (Event, bool, error) {
	return m.store.BigfundElementSpentEvent(id)
}

// Close closes the wallet manager.
func (m *Manager) Close() error {
	m.tg.Stop()
	return nil
}

// syncStore syncs the state of the store with the chain manager. The sync will
// complete when the store reaches the current tip or the context is canceled.
func syncStore(ctx context.Context, store Store, cm ChainManager, index types.ChainIndex, batchSize int) error {
	for index != cm.Tip() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		crus, caus, err := cm.UpdatesSince(index, batchSize)
		if err != nil {
			return fmt.Errorf("failed to subscribe to chain manager: %w", err)
		} else if err := store.UpdateChainState(crus, caus); err != nil {
			return fmt.Errorf("failed to update chain state: %w", err)
		}

		switch {
		case len(caus) > 0:
			index = caus[len(caus)-1].State.Index
		case len(crus) > 0:
			index = crus[len(crus)-1].State.Index
		}
	}
	return nil
}

// resetPool resets the tracked transaction pool state. This is used when the
// transaction pool is changed such as when a transaction is broadcast or
// when a reorg occurs.
//
// It is expected that the caller holds the manager's lock.
func (m *Manager) resetPool() {
	m.poolBIGCreated = make(map[types.BigfileOutputID]types.BigfileElement)
	m.poolBIGSpent = make(map[types.BigfileOutputID]bool)

	m.poolBFCreated = make(map[types.BigfundOutputID]types.BigfundElement)
	m.poolBFSpent = make(map[types.BigfundOutputID]bool)

	m.poolAddressSCSpent = make(map[types.Address][]types.BigfileOutputID)
	m.poolAddressSFSpent = make(map[types.Address][]types.BigfundOutputID)

	for _, txn := range m.chain.PoolTransactions() {
		for _, input := range txn.BigfileInputs {
			m.poolBIGSpent[input.ParentID] = true
			m.poolAddressSCSpent[input.UnlockConditions.UnlockHash()] = append(m.poolAddressSCSpent[input.UnlockConditions.UnlockHash()], input.ParentID)
			delete(m.poolBIGCreated, input.ParentID)
		}
		for i, bigo := range txn.BigfileOutputs {
			scoid := txn.BigfileOutputID(i)
			m.poolBIGCreated[scoid] = types.BigfileElement{
				ID:            scoid,
				StateElement:  types.StateElement{LeafIndex: types.UnassignedLeafIndex},
				BigfileOutput: bigo,
			}
		}

		for _, input := range txn.BigfundInputs {
			m.poolBFSpent[input.ParentID] = true
			delete(m.poolBFCreated, input.ParentID)
		}
		for i, bfo := range txn.BigfundOutputs {
			sfoid := txn.BigfundOutputID(i)
			m.poolBFCreated[sfoid] = types.BigfundElement{
				ID:            sfoid,
				StateElement:  types.StateElement{LeafIndex: types.UnassignedLeafIndex},
				BigfundOutput: bfo,
			}
		}
	}

	for _, txn := range m.chain.V2PoolTransactions() {
		for _, input := range txn.BigfileInputs {
			m.poolBIGSpent[input.Parent.ID] = true
			m.poolAddressSCSpent[input.Parent.BigfileOutput.Address] = append(m.poolAddressSCSpent[input.Parent.BigfileOutput.Address], input.Parent.ID)
			delete(m.poolBIGCreated, input.Parent.ID)
		}
		for i := range txn.BigfileOutputs {
			bige := txn.EphemeralBigfileOutput(i)
			m.poolBIGCreated[bige.ID] = bige
		}

		for _, input := range txn.BigfundInputs {
			m.poolBFSpent[input.Parent.ID] = true
			m.poolAddressSFSpent[input.Parent.BigfundOutput.Address] = append(m.poolAddressSFSpent[input.Parent.BigfundOutput.Address], input.Parent.ID)
			delete(m.poolBFCreated, input.Parent.ID)
		}
		for i := range txn.BigfundOutputs {
			bfe := txn.EphemeralBigfundOutput(i)
			m.poolBFCreated[bfe.ID] = bfe
		}
	}
}

func delta[T constraints.Integer | constraints.Float](a, b T) T {
	if cmp.Compare(a, b) > 0 {
		return a - b
	}
	return b - a
}

// NewManager creates a new wallet manager.
func NewManager(cm ChainManager, store Store, opts ...Option) (*Manager, error) {
	m := &Manager{
		indexMode:     IndexModePersonal,
		syncBatchSize: defaultSyncBatchSize,
		lockDuration:  time.Hour,

		chain: cm,
		store: store,
		log:   zap.NewNop(),
		tg:    threadgroup.New(),

		used: make(map[types.Hash256]time.Time),

		poolBIGSpent:   make(map[types.BigfileOutputID]bool),
		poolBIGCreated: make(map[types.BigfileOutputID]types.BigfileElement),

		poolBFSpent:   make(map[types.BigfundOutputID]bool),
		poolBFCreated: make(map[types.BigfundOutputID]types.BigfundElement),

		poolAddressSCSpent: make(map[types.Address][]types.BigfileOutputID),
		poolAddressSFSpent: make(map[types.Address][]types.BigfundOutputID),
	}

	for _, opt := range opts {
		opt(m)
	}

	// if the index mode is none, skip setting the index mode in the store
	// and return the manager
	if m.indexMode == IndexModeNone {
		return m, nil
	} else if err := store.SetIndexMode(m.indexMode); err != nil {
		return nil, err
	}

	// start a goroutine to sync the store with the chain manager
	reorgChan := make(chan struct{}, 1)
	reorgChan <- struct{}{}
	unsubscribe := cm.OnReorg(func(index types.ChainIndex) {
		select {
		case reorgChan <- struct{}{}:
		default:
		}
	})

	unsubscribePool := cm.OnPoolChange(func() {
		select {
		case reorgChan <- struct{}{}:
		default:
		}
	})

	go func() {
		ctx, cancel, err := m.tg.AddWithContext(context.Background())
		if errors.Is(err, threadgroup.ErrClosed) {
			return
		} else if err != nil {
			log.Panic("failed to add to threadgroup", zap.Error(err))
		}
		defer cancel()

		t := time.NewTicker(m.lockDuration / 2)
		defer t.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.mu.Lock()
				for id, ts := range m.used {
					if ts.Before(time.Now()) {
						delete(m.used, id)
					}
				}
				m.mu.Unlock()
			}
		}
	}()

	go func() {
		defer unsubscribe()
		defer unsubscribePool()

		log := m.log.Named("sync")
		ctx, cancel, err := m.tg.AddWithContext(context.Background())
		if err != nil {
			log.Panic("failed to add to threadgroup", zap.Error(err))
		}
		defer cancel()

		for {
			select {
			case <-ctx.Done():
				return
			case <-reorgChan:
			}

			m.mu.Lock()
			m.resetPool()
			// update the store
			lastTip, err := store.LastCommittedIndex()
			if err != nil {
				log.Panic("failed to get last committed index", zap.Error(err))
			}
			err = syncStore(ctx, store, cm, lastTip, m.syncBatchSize)
			if err != nil {
				switch {
				case errors.Is(err, context.Canceled):
					m.mu.Unlock()
					return
				case strings.Contains(err.Error(), "missing block at index"): // unfortunate, but not exposed by coreutils
					log.Warn("missing block at index, resetting chain state", zap.Stringer("id", lastTip.ID), zap.Uint64("height", lastTip.Height))
					if err := store.ResetChainState(); err != nil {
						log.Panic("failed to reset wallet state", zap.Error(err))
					}
					// trigger resync
					select {
					case reorgChan <- struct{}{}:
					default:
					}
				default:
					panic("failed to sync store: " + err.Error())
				}
			}
			m.mu.Unlock()
		}
	}()
	return m, nil
}
