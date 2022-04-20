package circuits

import (
	"embed"
	"encoding/json"
	"reflect"
	"sync"

	"github.com/pkg/errors"
)

var (
	//go:embed verificationKeys
	verificationKeysRes embed.FS
)

// CircuitID is alias for circuit identifier
type CircuitID string

const (
	// AuthCircuitID is a type that must be used for auth circuit id definition
	AuthCircuitID CircuitID = "auth"
	// StateTransitionCircuitID is a type that must be used for idState circuit definition
	StateTransitionCircuitID CircuitID = "stateTransition"
	// AtomicQueryMTPCircuitID is a type for credentialAtomicQueryMTP.circom
	AtomicQueryMTPCircuitID CircuitID = "credentialAtomicQueryMTP"
	// AtomicQuerySigCircuitID is a type for credentialAttrQuerySig.circom
	AtomicQuerySigCircuitID CircuitID = "credentialAtomicQuerySig"
	// AtomicQueryMTPCircuitID is a type for credentialAtomicQueryMTPWithRelay.circom
	AtomicQueryMTPWithRelayCircuitID CircuitID = "credentialAtomicQueryMTPWithRelay"
	// AtomicQuerySigCircuitID is a type for credentialAttrQuerySigWithRelay.circom
	AtomicQuerySigWithRelayCircuitID CircuitID = "credentialAtomicQuerySigWithRelay"
)

// ErrorCircuitIDNotFound returns if CircuitID is not registered
var ErrorCircuitIDNotFound = errors.New("circuit id not supported")

const (
	defaultMTLevels       = 40 // max MT levels, default value for identity circuits
	defaultValueArraySize = 16 // max value array size, default value for identity circuits
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
		Input:           AuthInputs{},
		Output:          &AuthPubSignals{},
		VerificationKey: embedFSLoader{"verificationKeys/auth.json"},
		ProvingKey:      nil,
	})

	RegisterCircuit(StateTransitionCircuitID, Data{
		Input:           StateTransitionInputs{},
		Output:          &StateTransitionOutput{},
		VerificationKey: embedFSLoader{"verificationKeys/stateTransition.json"},
		ProvingKey:      nil,
	})

	RegisterCircuit(AtomicQueryMTPCircuitID, Data{
		Input:           AtomicQueryMTPInputs{},
		Output:          &AtomicQueryMTPPubSignals{},
		VerificationKey: embedFSLoader{"verificationKeys/credentialAtomicQueryMTP.json"},
		ProvingKey:      nil,
	})

	RegisterCircuit(AtomicQueryMTPWithRelayCircuitID, Data{
		Input:           AtomicQueryMTPWithRelayInputs{},
		Output:          &AtomicQueryMTPWithRelayPubSignals{},
		VerificationKey: embedFSLoader{"verificationKeys/credentialAtomicQueryMTPWithRelay.json"},
		ProvingKey:      nil,
	})
	RegisterCircuit(AtomicQuerySigCircuitID, Data{
		Input:           AtomicQuerySigInputs{},
		Output:          &AtomicQuerySigPubSignals{},
		VerificationKey: embedFSLoader{"verificationKeys/credentialAtomicQuerySig.json"},
		ProvingKey:      nil,
	})
}

// BaseConfig base circuit's config, provides default configuration for default circuits
type BaseConfig struct {
	MTLevel        int // Max levels of MT
	ValueArraySize int // Size if value array in identity circuits
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

// InputMarshaller interface implemented by types that can marshal circuit `input` structures
type InputMarshaller interface {
	CircuitInputMarshal() ([]byte, error)
}

// PubSignalsUnmarshaller interface implemented by types that can unmarshal circuit `output` structures
type PubSignalsUnmarshaller interface {
	PubSignalsUnmarshal(data []byte) error
}

// JSONOutputMapper interface implemented by types that can unmarshal circuit `output` to map
type JSONOutputMapper interface {
	GetJSONObjMap() map[string]interface{}
}

// CircuitOutput interface implemented by types that can be registered in circuit registry
type CircuitOutput interface {
	PubSignalsUnmarshaller
	JSONOutputMapper
}

// KeyLoader interface, if key should be fetched from file system, CDN, IPFS etc,
//this interface may be implemented for key loading from a specific place
type KeyLoader interface {
	Load() ([]byte, error)
}

// Data circuit type
type Data struct {
	Input           InputMarshaller // input values type
	Output          CircuitOutput   // output values type
	VerificationKey KeyLoader
	ProvingKey      KeyLoader
}

// embedFSLoader read keys from embedded FS
type embedFSLoader struct {
	path string
}

// Load keys from embedded FS
func (m embedFSLoader) Load() ([]byte, error) {
	return verificationKeysRes.ReadFile(m.path)
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

	if err := json.Unmarshal(b, newPointer); err != nil {
		return nil, err
	}

	m := newPointer.(JSONOutputMapper).GetJSONObjMap()

	return m, nil
}

// GetVerificationKey return verification key registered for given CircuitID
func GetVerificationKey(id CircuitID) ([]byte, error) {
	circuitsLock.RLock()
	defer circuitsLock.RUnlock()

	circuit, ok := circuitsRegistry[id]
	if !ok {
		return nil, ErrorCircuitIDNotFound
	}

	return circuit.VerificationKey.Load()
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
