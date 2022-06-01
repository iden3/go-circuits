# go-circuits

### WARNING
All code here is experimental and WIP

[![Go Reference](https://pkg.go.dev/badge/github.com/iden3/go-circuits.svg)](https://pkg.go.dev/github.com/iden3/go-circuits)
[![Go Report Card](https://goreportcard.com/badge/github.com/iden3/go-circuits)](https://goreportcard.com/report/github.com/iden3/go-circuits)
### General description:

The library goal is to create a wrapper for private and public inputs for identity circuits

Repository of circuits implementation:  https://github.com/iden3/circuits

> Set of functionality for circuits inputs preparation, and public signals schema  retrieving
> 

### How to use :

- All circuits implement *InputsMarshaller*  and *PubSignalsUnmarshal* Interfaces
    
    ```go
  type InputsMarshaller interface {
        InputsMarshal() ([]byte, error)
  }


  type PubSignalsUnmarshaller interface {
        PubSignalsUnmarshal(data []byte) error
  }
    ```
  
- Example of usage:

At the moment you have to fill all needed attributes for a specific Inputs, take a look in test for each specific Input
 
```go
  inputs := AuthInputs{
        ID: identifier,
        AuthClaim: Claim{
            Claim:       claim,
            Proof:       claimEntryMTP,
            TreeState:   treeState,
            NonRevProof: &ClaimNonRevStatus{treeState, claimNonRevMTP},
        },
        Signature: signature,
        Challenge: challenge,
    }

    circuitInputJSON, err := inputs.InputsMarshal() // marshal JSON inputs for specific circuit in proper format
```
    
- It’s easy to extend Circuits mapping through registering custom Circuit Wrapper implementation
    
    ```go
    RegisterCircuit(CustomCircuitID, Data{
        Input:  CustomInputs{},
        Output: &CustomPubSignals{},
    })
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
        "$noop": NOOP,
        "$eq":   EQ,
        "$lt":   LT,
        "$gt":   GT,
        "$in":   IN,
        "$nin":  NIN,
    }
    ```
