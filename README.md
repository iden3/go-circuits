# go-circuits

### General description:

The library goal is to create a wrapper on top of standard circuits set

Repository of circuits implementation:  https://github.com/iden3/circuits

> Set of functionality for circuits inputs preparation, verification keys, and public signals schema  retrieving
> 

The current implementation supports the next circuits:

1. IDState and IDOwnership
2. CredentialAtomicQuery 
3. Authentication
4. KYC (Age and CountryCode credential) - custom

### How to use :

- All circuits implement *InputsPreparer*  and *BaseCircuit* Interfaces
    
    ```go
    type InputsPreparer interface {
    	PrepareInputs(i TypedInputs) (map[string]interface{}, error)
    }
    type BaseCircuit interface {
    	InputsPreparer
    	GetVerificationKey() VerificationKeyJSON
    	GetPublicSignalsSchema() PublicSchemaJSON
    }
    ```
    
- If you use an existing circuit
    
    ```go
    
    circuitID := "credentialAtomicQuery"
    circuitInputs := circuits.AtomicQueryInputs{
    			ID:               ...,
    			AuthClaim:        ...,
    			Challenge:        ...,
    			Signature:        ...,
    			Query:            ...,
    			Claim:            ...,
    			RevocationStatus: ...,
    }
    circuit, err := circuits.GetCircuit(circuits.CircuitID(circuitID))
    if err != nil {
    		return nil, nil, err
    }
    inputs, err := circuit.PrepareInputs(circuitInputs)
    if err != nil {
    	return nil, nil, err
    }
    ```
    
- It’s easy to extend Circuits mapping through registering custom Circuit Wrapper implementation, but it must implement *BaseCircuit* interface
    
    ```go
    RegisterCircuit(CustomQueryCircuitID, &CustomQueryCircuit{})
    ```
    
    ### Querying :
    
    The library defines the Query structure for atomic circuits and contains the mapping between query operation and its number. This library is not responsible for resolving SlotIndex for the claim field.
    
    ```go
    // Query represents basic request to claim slot verification
    type Query struct {
    	SlotIndex int
    	Value     *big.Int
    	Operator  int
    }
    
    // QueryOperators represents operators for atomic circuits
    var QueryOperators = map[string]int{
    	"$eq": 0,
    	"$lt": 1,
    	"$gt": 2,
    	"$ni": 3,
    	"$in": 4,
    }
    ```
