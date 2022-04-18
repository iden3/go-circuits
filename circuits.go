package circuits

import (
	"encoding/json"
	"reflect"
	"sync"

	"github.com/pkg/errors"
)

// BaseCircuit is generic circuit interface
type BaseCircuit interface {
	GetVerificationKey() VerificationKeyJSON
	GetJSONObjMap() map[string]interface{}
}

var defaultCircuits = map[CircuitID]BaseCircuit{}
var circuitsLock = new(sync.RWMutex)

// RegisterCircuit is factory for circuit init.
// This is typically done during init() in the method's implementation
func RegisterCircuit(id CircuitID, c BaseCircuit) {
	circuitsLock.Lock()
	defer circuitsLock.Unlock()
	defaultCircuits[id] = c
}

// ErrorCircuitIDNotFound returns if CircuitID is not registered
var ErrorCircuitIDNotFound = errors.New("circuit id not supported")

// UnmarshalCircuitOutput unmarshal bytes to specific circuit output type associated with id
func UnmarshalCircuitOutput(id CircuitID, b []byte) (map[string]interface{}, error) {
	circuitsLock.RLock()
	defer circuitsLock.RUnlock()

	circuitOutputType, exist := defaultCircuits[id]
	if !exist {
		return nil, ErrorCircuitIDNotFound
	}

	typ := reflect.TypeOf(circuitOutputType)
	val := reflect.New(typ.Elem())

	newPointer := val.Interface()

	if err := json.Unmarshal(b, newPointer); err != nil {
		return nil, err
	}

	m := newPointer.(BaseCircuit).GetJSONObjMap()

	return m, nil
}

// GetCircuit Gets a circuit implementation type by circuit ID
func GetCircuit(id CircuitID) (circuit BaseCircuit, err error) {
	circuitsLock.RLock()
	defer circuitsLock.RUnlock()

	circuit, ok := defaultCircuits[id]
	if !ok {
		return nil, ErrorCircuitIDNotFound
	}
	return circuit, nil
}
