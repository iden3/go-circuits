package circuits

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sync"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
)

// CircuitID is alias for circuit identifier
type CircuitID string

const (
	// AuthCircuitID is a type that must be used for auth.circom
	AuthCircuitID CircuitID = "auth"
	// AuthV2CircuitID is a type that must be used for authV2.circom
	AuthV2CircuitID CircuitID = "authV2"
	// StateTransitionCircuitID is a type that must be used for stateTransition.circom
	StateTransitionCircuitID CircuitID = "stateTransition"
	// AtomicQueryMTPCircuitID is a type for credentialAtomicQueryMTP.circom
	AtomicQueryMTPCircuitID CircuitID = "credentialAtomicQueryMTP"
	// AtomicQueryMTPV2CircuitID is a type for credentialAtomicQueryMTPV2.circom
	AtomicQueryMTPV2CircuitID CircuitID = "credentialAtomicQueryMTPV2"
	// AtomicQueryV3CircuitID is a type for credentialAtomicQueryV3.circom
	AtomicQueryV3CircuitID CircuitID = "credentialAtomicQueryV3-beta.1"
	// AtomicQueryMTPV2OnChainCircuitID is a type for credentialAtomicQueryMTPV2OnChain.circom
	AtomicQueryMTPV2OnChainCircuitID CircuitID = "credentialAtomicQueryMTPV2OnChain"
	// AtomicQuerySigCircuitID is a type for credentialAttrQuerySig.circom
	AtomicQuerySigCircuitID CircuitID = "credentialAtomicQuerySig"
	// AtomicQuerySigV2CircuitID is a type for credentialAttrQuerySigV2.circom
	AtomicQuerySigV2CircuitID CircuitID = "credentialAtomicQuerySigV2"
	// AtomicQuerySigV2OnChainCircuitID is a type for credentialAttrQuerySigV2OnChain.circom
	AtomicQuerySigV2OnChainCircuitID CircuitID = "credentialAtomicQuerySigV2OnChain"
	// AtomicQueryV3OnChainCircuitID is a type for credentialAtomicQueryV3OnChain.circom
	AtomicQueryV3OnChainCircuitID CircuitID = "credentialAtomicQueryV3OnChain-beta.1"
	// JsonLDAtomicQueryMTPCircuitID is a type for credentialJsonLDAtomicQueryMTP.circom
	JsonLDAtomicQueryMTPCircuitID CircuitID = "credentialJsonLDAtomicQueryMTP"
	// SybilMTPCircuitID is a type for sybilMTP.circom
	SybilMTPCircuitID CircuitID = "sybilCredentialAtomicMTP"
	// SybilSigCircuitID is a type for sybilSig.circom
	SybilSigCircuitID CircuitID = "sybilCredentialAtomicSig"
	// LinkedMultiQuery10CircuitID is a type for linkedMultiQuery10.circom
	LinkedMultiQuery10CircuitID CircuitID = "linkedMultiQuery10-beta.1"
)

// ErrorCircuitIDNotFound returns if CircuitID is not registered
var ErrorCircuitIDNotFound = errors.New("circuit id not supported")

const (
	defaultMTLevels        = 40 // max MT levels, default value for identity circuits
	defaultValueArraySize  = 64 // max value array size, default value for identity circuits
	defaultMTLevelsOnChain = 64 // max MT levels on chain, default value for identity circuits
	defaultMTLevelsClaim   = 32 // max MT levels of JSON-LD merklization on claim
)

var circuitsRegistry = map[CircuitID]Data{}
var circuitsLock = new(sync.RWMutex)

// RegisterCircuit is factory for circuit init.
// This is done during init() in the method's implementation
func RegisterCircuit(id CircuitID, c Data) {
	circuitsLock.Lock()
	defer circuitsLock.Unlock()

	circuitsRegistry[id] = c
}

// nolint // register supported circuit
func init() {

	RegisterCircuit(AuthCircuitID, Data{
		Input:  AuthInputs{},
		Output: &AuthPubSignals{},
	})

	RegisterCircuit(AuthV2CircuitID, Data{
		Input:  AuthV2Inputs{},
		Output: &AuthV2PubSignals{},
	})

	RegisterCircuit(StateTransitionCircuitID, Data{
		Input:  StateTransitionInputs{},
		Output: &StateTransitionPubSignals{},
	})

	RegisterCircuit(AtomicQueryMTPCircuitID, Data{
		Input:  AtomicQueryMTPInputs{},
		Output: &AtomicQueryMTPPubSignals{},
	})

	RegisterCircuit(AtomicQueryMTPV2CircuitID, Data{
		Input:  AtomicQueryMTPV2Inputs{},
		Output: &AtomicQueryMTPV2PubSignals{},
	})

	RegisterCircuit(AtomicQuerySigCircuitID, Data{
		Input:  AtomicQuerySigInputs{},
		Output: &AtomicQuerySigPubSignals{},
	})

	RegisterCircuit(AtomicQuerySigV2CircuitID, Data{
		Input:  AtomicQuerySigV2Inputs{},
		Output: &AtomicQuerySigV2PubSignals{},
	})

	RegisterCircuit(AtomicQueryV3CircuitID, Data{
		Input:  AtomicQueryV3Inputs{},
		Output: &AtomicQueryV3PubSignals{},
	})

	RegisterCircuit(AtomicQuerySigV2OnChainCircuitID, Data{
		Input:  AtomicQuerySigV2OnChainInputs{},
		Output: &AtomicQuerySigV2OnChainPubSignals{},
	})

	RegisterCircuit(AtomicQueryMTPV2OnChainCircuitID, Data{
		Input:  AtomicQueryMTPV2OnChainInputs{},
		Output: &AtomicQueryMTPV2OnChainPubSignals{},
	})

	RegisterCircuit(SybilMTPCircuitID, Data{
		Input:  SybilAtomicMTPInputs{},
		Output: &SybilAtomicMTPPubSignals{},
	})

	RegisterCircuit(SybilSigCircuitID, Data{
		Input:  SybilAtomicSigInputs{},
		Output: &SybilAtomicSigPubSignals{},
	})

	RegisterCircuit(AtomicQueryV3OnChainCircuitID, Data{
		Input:  AtomicQueryV3OnChainInputs{},
		Output: &AtomicQueryV3OnChainPubSignals{},
	})
}

// BaseConfig base circuit's config, provides default configuration for default circuits
type BaseConfig struct {
	MTLevel        int // Max levels of MT
	ValueArraySize int // Size if value array in identity circuits
	MTLevelOnChain int // Max levels of MT on chain
	MTLevelClaim   int // Max level of JSONLD claim
}

// GetMTLevel max circuit MT levels
func (c BaseConfig) GetMTLevel() int {
	if c.MTLevel == 0 {
		return defaultMTLevels
	}
	return c.MTLevel
}

// GetValueArrSize return size of circuits value array size
func (c BaseConfig) GetValueArrSize() int {
	if c.ValueArraySize == 0 {
		return defaultValueArraySize
	}
	return c.ValueArraySize
}

// GetMTLevelOnChain max circuit MT levels on chain
func (c BaseConfig) GetMTLevelOnChain() int {
	if c.MTLevelOnChain == 0 {
		return defaultMTLevelsOnChain
	}
	return c.MTLevelOnChain
}

// GetMTLevelsClaim max jsonld Claim levels
func (c BaseConfig) GetMTLevelsClaim() int {
	if c.MTLevelClaim == 0 {
		return defaultMTLevelsClaim
	}
	return c.MTLevelClaim

}

// InputsMarshaller interface implemented by types that can marshal circuit `input` structures
type InputsMarshaller interface {
	InputsMarshal() ([]byte, error)
}

// PubSignalsUnmarshaller interface implemented by types that can unmarshal circuit `output` structures
type PubSignalsUnmarshaller interface {
	PubSignalsUnmarshal(data []byte) error
}

// PubSignalsMapper interface implemented by types that can unmarshal circuit `output` to map
type PubSignalsMapper interface {
	GetObjMap() map[string]interface{}
}

// PubSignals interface implemented by types that can be registered in circuit registry
type PubSignals interface {
	PubSignalsUnmarshaller
	PubSignalsMapper
}

// PublicStatesInfoProvider interface should be implemented by Inputs types that
// can return public states info
type PublicStatesInfoProvider interface {
	GetPublicStatesInfo() (StatesInfo, error)
}

// StatesInfoProvider interface should be implemented by PubSignals types that
// can return states info
type StatesInfoProvider interface {
	GetStatesInfo() (StatesInfo, error)
}

// StatesInfo struct. A collection of states and gists
type StatesInfo struct {
	States []State `json:"states"`
	Gists  []Gist  `json:"gists"`
}

// State information
type State struct {
	ID    core.ID         `json:"id"`
	State merkletree.Hash `json:"state"`
}

func (s *State) UnmarshalJSON(i []byte) error {
	var j struct {
		ID    *jsonInt `json:"id"`
		State *jsonInt `json:"state"`
	}
	err := json.Unmarshal(i, &j)
	if err != nil {
		return err
	}

	if j.ID == nil {
		return errors.New("id is nil")
	}
	s.ID, err = core.IDFromInt(j.ID.BigInt())
	if err != nil {
		return err
	}

	h, err := merkletree.NewHashFromBigInt(j.State.BigInt())
	if err != nil {
		return err
	}
	s.State = *h

	return nil
}

func (s State) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.Grow(256) // 20 + 2*78 + padding ≈ 256
	b.Write([]byte(`{"id":"`))
	b.Write([]byte(s.ID.BigInt().String()))
	b.Write([]byte(`","state":"`))
	b.Write([]byte(s.State.BigInt().String()))
	b.Write([]byte(`"}`))
	return b.Bytes(), nil
}

// Gist information
type Gist struct {
	ID   core.ID         `json:"id"`
	Root merkletree.Hash `json:"root"`
}

func (g *Gist) UnmarshalJSON(i []byte) error {
	var j struct {
		ID   *jsonInt `json:"id"`
		Root *jsonInt `json:"root"`
	}
	err := json.Unmarshal(i, &j)
	if err != nil {
		return err
	}

	if j.ID == nil {
		return errors.New("id is nil")
	}
	g.ID, err = core.IDFromInt(j.ID.BigInt())
	if err != nil {
		return err
	}

	h, err := merkletree.NewHashFromBigInt(j.Root.BigInt())
	if err != nil {
		return err
	}
	g.Root = *h

	return nil
}

func (g Gist) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.Grow(256) // 20 + 2*78 + padding ≈ 256
	b.Write([]byte(`{"id":"`))
	b.Write([]byte(g.ID.BigInt().String()))
	b.Write([]byte(`","root":"`))
	b.Write([]byte(g.Root.BigInt().String()))
	b.Write([]byte(`"}`))
	return b.Bytes(), nil
}

// KeyLoader interface, if key should be fetched from file system, CDN, IPFS etc,
// this interface may be implemented for key loading from a specific place
type KeyLoader interface {
	Load() ([]byte, error)
}

// Data circuit type
type Data struct {
	Input  InputsMarshaller // input values type
	Output PubSignals       // output values type
}

// UnmarshalCircuitOutput unmarshal bytes to specific circuit Output type associated with id
func UnmarshalCircuitOutput(id CircuitID, b []byte) (map[string]interface{}, error) {
	circuitsLock.RLock()
	defer circuitsLock.RUnlock()

	circuitOutputType, exist := circuitsRegistry[id]
	if !exist {
		return nil, ErrorCircuitIDNotFound
	}

	typ := reflect.TypeOf(circuitOutputType.Output)
	val := reflect.New(typ.Elem())

	newPointer := val.Interface()

	err := newPointer.(PubSignalsUnmarshaller).PubSignalsUnmarshal(b)
	if err != nil {
		return nil, err
	}

	m := newPointer.(PubSignalsMapper).GetObjMap()

	return m, nil
}

// GetCircuit return circuit Data
func GetCircuit(id CircuitID) (*Data, error) {
	circuitsLock.RLock()
	defer circuitsLock.RUnlock()

	circuit, ok := circuitsRegistry[id]
	if !ok {
		return nil, ErrorCircuitIDNotFound
	}
	return &circuit, nil
}
