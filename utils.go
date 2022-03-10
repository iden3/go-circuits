package circuits

import (
	"github.com/iden3/go-iden3-core"
	"math/big"

	"github.com/pkg/errors"

	"github.com/iden3/go-merkletree-sql"
)

// PrepareSiblings prepare siblings for zk zk
func PrepareSiblings(siblings []*merkletree.Hash, levels int) []*big.Int {
	// siblings := mtproof.AllSiblings()
	// Add the rest of empty levels to the siblings
	for i := len(siblings); i < levels; i++ {
		siblings = append(siblings, &merkletree.HashZero)
	}
	siblingsBigInt := make([]*big.Int, len(siblings))
	for i, sibling := range siblings {
		siblingsBigInt[i] = sibling.BigInt()
	}
	return siblingsBigInt
}

// PrepareCircuitArrayValues padding values to size. Validate array size and throw an exception if array is bigger
// than size
// if array is bigger circuit cannot compile because number of inputs does not match
func PrepareCircuitArrayValues(arr []*big.Int, size int) ([]*big.Int, error) {

	if len(arr) > size {
		return nil, errors.Errorf("array size {%d} is bigger max expected size {%d}", len(arr), size)
	}

	// Add the empty values
	for i := len(arr); i < size; i++ {
		arr = append(arr, new(big.Int))
	}

	return arr, nil
}

func mergeMaps(maps ...map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

func bigIntArrayToStringArray(array []*big.Int) []string {
	res := make([]string, 0)
	for i := range array {
		res = append(res, array[i].String())
	}
	return res
}

func getSlots(claim *core.Claim) []*big.Int {
	inputs := make([]*big.Int, 0)

	entry := claim.TreeEntry()

	indexes := entry.Index()
	values := entry.Value()
	for _, index := range indexes {
		inputs = append(inputs, index.BigInt())
	}
	for _, value := range values {
		inputs = append(inputs, value.BigInt())
	}
	return inputs
}
