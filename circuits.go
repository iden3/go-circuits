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
	res embed.FS
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

var defaultCircuits = map[CircuitID]Data{}
var circuitsLock = new(sync.RWMutex)

// RegisterCircuit is factory for circuit init.
// This is done during init() in the method's implementation
func RegisterCircuit(id CircuitID, c Data) {
	circuitsLock.Lock()
	defer circuitsLock.Unlock()

	defaultCircuits[id] = c
}

// nolint // register supported circuit
func init() {

	RegisterCircuit(AuthCircuitID, Data{
		input:           AuthInputs{},
		output:          &AuthOutputs{},
		verificationKey: embedFSLoader{"verificationKeys/auth.json"},
		provingKey:      nil,
	})

	RegisterCircuit(StateTransitionCircuitID, Data{
		input:           StateTransitionInputs{},
		output:          &StateTransitionOutput{},
		verificationKey: embedFSLoader{"verificationKeys/stateTransition.json"},
		provingKey:      nil,
	})

	RegisterCircuit(AtomicQueryMTPCircuitID, Data{
		input:           AtomicQueryMTPInputs{},
		output:          &AtomicQueryMTPOutputs{},
		verificationKey: embedFSLoader{"verificationKeys/credentialAtomicQueryMTP.json"},
		provingKey:      nil,
	})

	RegisterCircuit(AtomicQueryMTPWithRelayCircuitID, Data{
		input:           AtomicQueryMTPWithRelayInputs{},
		output:          &AtomicQueryMTPWithRelayOutputs{},
		verificationKey: embedFSLoader{"verificationKeys/credentialAtomicQueryMTPWithRelay.json"},
		provingKey:      nil,
	})
	RegisterCircuit(AtomicQuerySigCircuitID, Data{
		input:           AtomicQuerySigInputs{},
		output:          &AtomicQuerySigOutputs{},
		verificationKey: embedFSLoader{"verificationKeys/credentialAtomicQuerySig.json"},
		provingKey:      nil,
	})
}

// BaseConfig base circuit's config, all default circuits use default configuration
// If need it can be changed
type BaseConfig struct {
	MTLevel        int // Max levels of MT
	ValueArraySize int // Size if value array in identity circuits
}

// GetMTLevel max MT levels
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

type InputMarshaller interface {
	CircuitInputMarshal() ([]byte, error)
}

type OutputUnmarshaller interface {
	CircuitOutputUnmarshal(data []byte) error
}

// BaseCircuit is generic circuit interface
type BaseCircuit interface {
	GetJSONObjMap() map[string]interface{}
}

// KeyLoader interface, if key should be fetched from file system, CDN, IPFS etc,
//this interface may be implemented for key loading from a specific place
type KeyLoader interface {
	Load() ([]byte, error)
}

// Data base circuit
type Data struct {
	input           InputMarshaller
	output          OutputUnmarshaller
	verificationKey KeyLoader
	provingKey      KeyLoader
}

// embedFSLoader read verification keys from embedded FS
type embedFSLoader struct {
	path string
}

// Load keys from embedded FS
func (m embedFSLoader) Load() ([]byte, error) {
	return res.ReadFile(m.path)
}

// UnmarshalCircuitOutput unmarshal bytes to specific circuit output type associated with id
func UnmarshalCircuitOutput(id CircuitID, b []byte) (map[string]interface{}, error) {
	circuitsLock.RLock()
	defer circuitsLock.RUnlock()

	circuitOutputType, exist := defaultCircuits[id]
	if !exist {
		return nil, ErrorCircuitIDNotFound
	}

	typ := reflect.TypeOf(circuitOutputType.output)
	val := reflect.New(typ.Elem())

	newPointer := val.Interface()

	if err := json.Unmarshal(b, newPointer); err != nil {
		return nil, err
	}

	m := newPointer.(BaseCircuit).GetJSONObjMap()

	return m, nil
}

// GetVerificationKey return verification key registered for given CircuitID
func GetVerificationKey(id CircuitID) ([]byte, error) {
	circuitsLock.RLock()
	defer circuitsLock.RUnlock()

	circuit, ok := defaultCircuits[id]
	if !ok {
		return nil, ErrorCircuitIDNotFound
	}

	return circuit.verificationKey.Load()
}

// GetCircuit return circuit Data
func GetCircuit(id CircuitID) (*Data, error) {
	circuitsLock.RLock()
	defer circuitsLock.RUnlock()

	circuit, ok := defaultCircuits[id]
	if !ok {
		return nil, ErrorCircuitIDNotFound
	}
	return &circuit, nil
}
