package circuits

import (
	"reflect"
	"sync"

	"github.com/pkg/errors"
)

// CircuitID is alias for circuit identifier
type CircuitID string

const (
	// AuthCircuitID is a type that must be used for auth.circom
	AuthCircuitID CircuitID = "auth"
	// StateTransitionCircuitID is a type that must be used for stateTransition.circom
	StateTransitionCircuitID CircuitID = "stateTransition"
	// AtomicQueryMTPCircuitID is a type for credentialAtomicQueryMTP.circom
	AtomicQueryMTPCircuitID CircuitID = "credentialAtomicQueryMTP"
	// AtomicQuerySigCircuitID is a type for credentialAttrQuerySig.circom
	AtomicQuerySigCircuitID CircuitID = "credentialAtomicQuerySig"
	// AtomicQuerySigOnChainSmtCircuitID is a type for credentialAttrQuerySigOnChainSmt.circom
	AtomicQuerySigOnChainSmtCircuitID CircuitID = "credentialAtomicQuerySigOnChainSmt"
)

// ErrorCircuitIDNotFound returns if CircuitID is not registered
var ErrorCircuitIDNotFound = errors.New("circuit id not supported")

const (
	defaultMTLevels        = 32 // max MT levels, default value for identity circuits
	defaultMTLevelsOnChain = 32 // max MT levels on chain, default value for identity circuits
	defaultValueArraySize  = 64 // max value array size, default value for identity circuits
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

	RegisterCircuit(StateTransitionCircuitID, Data{
		Input:  StateTransitionInputs{},
		Output: &StateTransitionPubSignals{},
	})

	RegisterCircuit(AtomicQueryMTPCircuitID, Data{
		Input:  AtomicQueryMTPInputs{},
		Output: &AtomicQueryMTPPubSignals{},
	})

	RegisterCircuit(AtomicQuerySigCircuitID, Data{
		Input:  AtomicQuerySigInputs{},
		Output: &AtomicQuerySigPubSignals{},
	})

	RegisterCircuit(AtomicQuerySigOnChainSmtCircuitID, Data{
		Input:  AtomicQuerySigOnChainSmtInputs{},
		Output: &AtomicQuerySigOnChainSmtPubSignals{},
	})
}

// BaseConfig base circuit's config, provides default configuration for default circuits
type BaseConfig struct {
	MTLevel        int // Max levels of MT
	MTLevelOnChain int // Max levels of MT on chain
	ValueArraySize int // Size if value array in identity circuits
}

// GetMTLevel max circuit MT levels
func (c BaseConfig) GetMTLevel() int {
	if c.MTLevel == 0 {
		return defaultMTLevels
	}
	return c.MTLevel
}

// GetMTLevel max circuit MT levels on chain
func (c BaseConfig) GetMTLevelOnChain() int {
	if c.MTLevelOnChain == 0 {
		return defaultMTLevelsOnChain
	}
	return c.MTLevelOnChain
}

// GetValueArrSize return size of circuits value array size
func (c BaseConfig) GetValueArrSize() int {
	if c.ValueArraySize == 0 {
		return defaultValueArraySize
	}
	return c.ValueArraySize
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

// KeyLoader interface, if key should be fetched from file system, CDN, IPFS etc,
//this interface may be implemented for key loading from a specific place
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
