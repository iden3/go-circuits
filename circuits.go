package circuits

import (
	"fmt"
	"sync"
)

// BaseCircuit is generic circuit interface
type BaseCircuit interface {
	GetVerificationKey() VerificationKeyJSON
	GetPublicSignalsSchema() PublicSchemaJSON
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

// GetCircuit Gets a circuit implementation by circuit ID
func GetCircuit(id CircuitID) (circuit BaseCircuit, err error) {
	circuitsLock.RLock()
	defer circuitsLock.RUnlock()

	circuit, ok := defaultCircuits[id]
	if !ok {
		return nil, fmt.Errorf(
			"circuit with id %s is not supported by library", id)
	}
	return circuit, nil
}
