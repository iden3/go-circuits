package circuits

import "math/big"

// Query represents basic request to claim slot verification
type Query struct {
	SlotIndex int
	Values    []*big.Int
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
