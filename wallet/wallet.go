package wallet

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"go.thebigfile.com/core/consensus"
	"go.thebigfile.com/core/types"
	"go.thebigfile.com/coreutils/wallet"
)

// event types indicate the source of an event. Events can
// either be created by sending Bigfiles between addresses or they can be
// created by consensus (e.g. a miner payout, a bigfund claim, or a contract).
const (
	EventTypeMinerPayout       = wallet.EventTypeMinerPayout
	EventTypeFoundationSubsidy = wallet.EventTypeFoundationSubsidy
	EventTypeBigfundClaim      = wallet.EventTypeBigfundClaim

	EventTypeV1Transaction        = wallet.EventTypeV1Transaction
	EventTypeV1ContractResolution = wallet.EventTypeV1ContractResolution

	EventTypeV2Transaction        = wallet.EventTypeV2Transaction
	EventTypeV2ContractResolution = wallet.EventTypeV2ContractResolution
)

type (
	// An EventPayout represents a miner payout, bigfund claim, or foundation
	// subsidy.
	EventPayout = wallet.EventPayout
	// An EventV1Transaction pairs a v1 transaction with its spent bigfile and
	// bigfund elements.
	EventV1Transaction = wallet.EventV1Transaction
	// An EventV1ContractResolution represents a file contract payout from a v1
	// contract.
	EventV1ContractResolution = wallet.EventV1ContractResolution
	// EventV2Transaction is a transaction event that includes the transaction
	EventV2Transaction = wallet.EventV2Transaction
	// An EventV2ContractResolution represents a file contract payout from a v2
	// contract.
	EventV2ContractResolution = wallet.EventV2ContractResolution

	// EventData is the data associated with an event.
	EventData = wallet.EventData
	// An Event is a record of a consensus event that affects the wallet.
	Event = wallet.Event
)

type (
	// Balance is a summary of a bigfile and bigfund balance
	Balance struct {
		Bigfiles         types.Currency `json:"bigfiles"`
		ImmatureBigfiles types.Currency `json:"immatureBigfiles"`
		Bigfunds         uint64         `json:"bigfunds"`
	}

	// An ID is a unique identifier for a wallet.
	ID int64

	// A Wallet is a collection of addresses and metadata.
	Wallet struct {
		ID          ID              `json:"id"`
		Name        string          `json:"name"`
		Description string          `json:"description"`
		DateCreated time.Time       `json:"dateCreated"`
		LastUpdated time.Time       `json:"lastUpdated"`
		Metadata    json.RawMessage `json:"metadata"`
	}

	// A Address is an address associated with a wallet.
	Address struct {
		Address     types.Address      `json:"address"`
		Description string             `json:"description"`
		SpendPolicy *types.SpendPolicy `json:"spendPolicy,omitempty"`
		Metadata    json.RawMessage    `json:"metadata"`
	}

	// An UnspentBigfileElement is an unspent bigfile output paired
	// with the number of confirmations.
	UnspentBigfileElement struct {
		types.BigfileElement
		Confirmations uint64 `json:"confirmations"`
	}

	// An UnspentBigfundElement is an unspent bigfund output paired
	// with the number of confirmations.
	UnspentBigfundElement struct {
		types.BigfundElement
		Confirmations uint64 `json:"confirmations"`
	}

	// A ChainUpdate is a set of changes to the consensus state.
	ChainUpdate interface {
		BigfileElementDiffs() []consensus.BigfileElementDiff
		BigfundElementDiffs() []consensus.BigfundElementDiff
		FileContractElementDiffs() []consensus.FileContractElementDiff
		V2FileContractElementDiffs() []consensus.V2FileContractElementDiff
	}
)

// ErrNotFound is returned when a requested wallet or address is not found.
var ErrNotFound = errors.New("not found")

// UnmarshalText implements encoding.TextUnmarshaler.
func (w *ID) UnmarshalText(buf []byte) error {
	id, err := strconv.ParseInt(string(buf), 10, 64)
	if err != nil {
		return err
	}
	*w = ID(id)
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (w ID) MarshalText() ([]byte, error) {
	return []byte(strconv.FormatInt(int64(w), 10)), nil
}

// StandardTransactionSignature is the most common form of TransactionSignature.
// It covers the entire transaction, references a sole public key, and has no
// timelock.
func StandardTransactionSignature(id types.Hash256) types.TransactionSignature {
	return types.TransactionSignature{
		ParentID:       id,
		CoveredFields:  types.CoveredFields{WholeTransaction: true},
		PublicKeyIndex: 0,
	}
}

// SignTransaction signs txn with the given key. The TransactionSignature object
// must already be present in txn at the given index.
func SignTransaction(cs consensus.State, txn *types.Transaction, sigIndex int, key types.PrivateKey) {
	tsig := &txn.Signatures[sigIndex]
	var sigHash types.Hash256
	if tsig.CoveredFields.WholeTransaction {
		sigHash = cs.WholeSigHash(*txn, tsig.ParentID, tsig.PublicKeyIndex, tsig.Timelock, tsig.CoveredFields.Signatures)
	} else {
		sigHash = cs.PartialSigHash(*txn, tsig.CoveredFields)
	}
	sig := key.SignHash(sigHash)
	tsig.Signature = sig[:]
}

// AppliedEvents extracts a list of relevant events from a chain update.
func AppliedEvents(cs consensus.State, b types.Block, cu ChainUpdate, relevant func(types.Address) bool) (events []Event) {
	addEvent := func(id types.Hash256, maturityHeight uint64, eventType string, v wallet.EventData, relevant []types.Address) {
		// dedup relevant addresses
		seen := make(map[types.Address]bool)
		unique := relevant[:0]
		for _, addr := range relevant {
			if !seen[addr] {
				unique = append(unique, addr)
				seen[addr] = true
			}
		}

		events = append(events, Event{
			ID:             id,
			Timestamp:      b.Timestamp,
			Index:          cs.Index,
			MaturityHeight: maturityHeight,
			Relevant:       unique,
			Type:           eventType,
			Data:           v,
		})
	}

	anythingRelevant := func() bool {
		for _, biged := range cu.BigfileElementDiffs() {
			if relevant(biged.BigfileElement.BigfileOutput.Address) {
				return true
			}
		}
		for _, sfed := range cu.BigfundElementDiffs() {
			if relevant(sfed.BigfundElement.BigfundOutput.Address) {
				return true
			}
		}
		return false
	}()
	if !anythingRelevant {
		return nil
	}

	// collect all elements
	biges := make(map[types.BigfileOutputID]types.BigfileElement)
	bfes := make(map[types.BigfundOutputID]types.BigfundElement)
	for _, biged := range cu.BigfileElementDiffs() {
		bige := biged.BigfileElement
		bige.StateElement.MerkleProof = nil
		biges[bige.ID] = bige
	}
	for _, sfed := range cu.BigfundElementDiffs() {
		bfe := sfed.BigfundElement
		bfe.StateElement.MerkleProof = nil
		bfes[bfe.ID] = bfe
	}

	// handle v1 transactions
	for _, txn := range b.Transactions {
		addresses := make(map[types.Address]bool)
		e := &wallet.EventV1Transaction{
			Transaction:          txn,
			SpentBigfileElements: make([]types.BigfileElement, 0, len(txn.BigfileInputs)),
			SpentBigfundElements: make([]types.BigfundElement, 0, len(txn.BigfundInputs)),
		}

		for _, bigi := range txn.BigfileInputs {
			bige, ok := biges[bigi.ParentID]
			if !ok {
				continue
			}

			e.SpentBigfileElements = append(e.SpentBigfileElements, bige)
			if relevant(bige.BigfileOutput.Address) {
				addresses[bige.BigfileOutput.Address] = true
			}
		}
		for _, bigo := range txn.BigfileOutputs {
			if relevant(bigo.Address) {
				addresses[bigo.Address] = true
			}
		}

		for _, bfi := range txn.BigfundInputs {
			bfe, ok := bfes[bfi.ParentID]
			if !ok {
				continue
			}

			e.SpentBigfundElements = append(e.SpentBigfundElements, bfe)
			if relevant(bfe.BigfundOutput.Address) {
				addresses[bfe.BigfundOutput.Address] = true
			}

			bige, ok := biges[bfi.ParentID.ClaimOutputID()]
			if ok && relevant(bige.BigfileOutput.Address) && !bige.BigfileOutput.Value.IsZero() {
				addEvent(types.Hash256(bige.ID), bige.MaturityHeight, EventTypeBigfundClaim, wallet.EventPayout{
					BigfileElement: bige,
				}, []types.Address{bfi.ClaimAddress})
			}
		}
		for _, bfo := range txn.BigfundOutputs {
			if relevant(bfo.Address) {
				addresses[bfo.Address] = true
			}
		}

		// skip transactions with no relevant addresses
		if len(addresses) == 0 {
			continue
		}

		relevant := make([]types.Address, 0, len(addresses))
		for addr := range addresses {
			relevant = append(relevant, addr)
		}

		addEvent(types.Hash256(txn.ID()), cs.Index.Height, EventTypeV1Transaction, e, relevant) // transaction maturity height is the current block height
	}

	// handle v2 transactions
	for _, txn := range b.V2Transactions() {
		addresses := make(map[types.Address]bool)
		for _, bigi := range txn.BigfileInputs {
			if !relevant(bigi.Parent.BigfileOutput.Address) {
				continue
			}
			addresses[bigi.Parent.BigfileOutput.Address] = true
		}
		for _, bigo := range txn.BigfileOutputs {
			if !relevant(bigo.Address) {
				continue
			}
			addresses[bigo.Address] = true
		}
		for _, bfi := range txn.BigfundInputs {
			if !relevant(bfi.Parent.BigfundOutput.Address) {
				continue
			}
			addresses[bfi.Parent.BigfundOutput.Address] = true

			bige, ok := biges[types.BigfundOutputID(bfi.Parent.ID).V2ClaimOutputID()]
			if ok && relevant(bfi.ClaimAddress) && !bige.BigfileOutput.Value.IsZero() {
				addEvent(types.Hash256(bige.ID), bige.MaturityHeight, EventTypeBigfundClaim, wallet.EventPayout{
					BigfileElement: bige,
				}, []types.Address{bfi.ClaimAddress})
			}
		}
		for _, bigo := range txn.BigfundOutputs {
			if !relevant(bigo.Address) {
				continue
			}
			addresses[bigo.Address] = true
		}

		// skip transactions with no relevant addresses
		if len(addresses) == 0 {
			continue
		}

		ev := wallet.EventV2Transaction(txn)
		relevant := make([]types.Address, 0, len(addresses))
		for addr := range addresses {
			relevant = append(relevant, addr)
		}
		addEvent(types.Hash256(txn.ID()), cs.Index.Height, EventTypeV2Transaction, ev, relevant) // transaction maturity height is the current block height
	}

	// handle contracts
	for _, fced := range cu.FileContractElementDiffs() {
		if !fced.Resolved {
			continue
		}

		fce := fced.FileContractElement
		fce.StateElement.MerkleProof = nil

		if fced.Valid {
			for i := range fce.FileContract.ValidProofOutputs {
				address := fce.FileContract.ValidProofOutputs[i].Address
				if !relevant(address) {
					continue
				}

				element := biges[types.FileContractID(fce.ID).ValidOutputID(i)]
				addEvent(types.Hash256(element.ID), element.MaturityHeight, EventTypeV1ContractResolution, wallet.EventV1ContractResolution{
					Parent:         fce,
					BigfileElement: element,
					Missed:         false,
				}, []types.Address{address})
			}
		} else {
			for i := range fce.FileContract.MissedProofOutputs {
				address := fce.FileContract.MissedProofOutputs[i].Address
				if !relevant(address) {
					continue
				}

				element := biges[types.FileContractID(fce.ID).MissedOutputID(i)]
				addEvent(types.Hash256(element.ID), element.MaturityHeight, EventTypeV1ContractResolution, wallet.EventV1ContractResolution{
					Parent:         fce,
					BigfileElement: element,
					Missed:         true,
				}, []types.Address{address})
			}
		}
	}

	for _, fced := range cu.V2FileContractElementDiffs() {
		fce := fced.V2FileContractElement
		res := fced.Resolution
		if res == nil {
			continue
		}
		fce.StateElement.MerkleProof = nil

		var missed bool
		if _, ok := res.(*types.V2FileContractExpiration); ok {
			missed = true
		}

		if relevant(fce.V2FileContract.HostOutput.Address) {
			element := biges[types.FileContractID(fce.ID).V2HostOutputID()]
			addEvent(types.Hash256(element.ID), element.MaturityHeight, EventTypeV2ContractResolution, wallet.EventV2ContractResolution{
				Resolution: types.V2FileContractResolution{
					Parent:     fce,
					Resolution: res,
				},
				BigfileElement: element,
				Missed:         missed,
			}, []types.Address{fce.V2FileContract.HostOutput.Address})
		}

		if relevant(fce.V2FileContract.RenterOutput.Address) {
			element := biges[types.FileContractID(fce.ID).V2RenterOutputID()]
			addEvent(types.Hash256(element.ID), element.MaturityHeight, EventTypeV2ContractResolution, wallet.EventV2ContractResolution{
				Resolution: types.V2FileContractResolution{
					Parent:     fce,
					Resolution: res,
				},
				BigfileElement: element,
				Missed:         missed,
			}, []types.Address{fce.V2FileContract.RenterOutput.Address})
		}
	}

	// handle block rewards
	for i := range b.MinerPayouts {
		if relevant(b.MinerPayouts[i].Address) {
			element := biges[cs.Index.ID.MinerOutputID(i)]
			addEvent(types.Hash256(element.ID), element.MaturityHeight, EventTypeMinerPayout, wallet.EventPayout{
				BigfileElement: element,
			}, []types.Address{b.MinerPayouts[i].Address})
		}
	}

	// handle foundation subsidy
	if relevant(cs.FoundationManagementAddress) {
		element, ok := biges[cs.Index.ID.FoundationOutputID()]
		if ok {
			addEvent(types.Hash256(element.ID), element.MaturityHeight, EventTypeFoundationSubsidy, wallet.EventPayout{
				BigfileElement: element,
			}, []types.Address{element.BigfileOutput.Address})
		}
	}

	return events
}

// NewSeedPhrase generates a random seed phrase.
func NewSeedPhrase() string {
	return wallet.NewSeedPhrase()
}

// SeedFromPhrase derives a 32-byte seed from the supplied phrase.
func SeedFromPhrase(seed *[32]byte, phrase string) error {
	return wallet.SeedFromPhrase(seed, phrase)
}

// KeyFromSeed returns the Ed25519 key derived from the supplied seed and index.
func KeyFromSeed(seed *[32]byte, index uint64) types.PrivateKey {
	return wallet.KeyFromSeed(seed, index)
}
