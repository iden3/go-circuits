package circuits

import (
	"math/big"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql"
	"github.com/pkg/errors"
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

func PrepareSiblingsStr(siblings []*merkletree.Hash, levels int) []string {
	// siblings := mtproof.AllSiblings()
	// Add the rest of empty levels to the siblings
	for i := len(siblings); i < levels; i++ {
		siblings = append(siblings, &merkletree.HashZero)
	}
	return HashToStr(siblings)
}

func HashToStr(siblings []*merkletree.Hash) []string {
	siblingsStr := make([]string, len(siblings))
	for i, sibling := range siblings {
		siblingsStr[i] = sibling.BigInt().String()
	}
	return siblingsStr
}

func BigIntToStr(s []*big.Int) []string {
	siblingsStr := make([]string, len(s))
	for i, sibling := range s {
		siblingsStr[i] = sibling.String()
	}
	return siblingsStr
}

// PrepareCircuitArrayValues padding values to size. Validate array size and throw an exception if array is bigger
// than size
// if array is bigger circuit cannot compile because number of inputs does not match
func PrepareCircuitArrayValues(arr []*big.Int, size int) ([]*big.Int, error) {
	if len(arr) > size {
		return nil, errors.Errorf("array size {%d} is bigger max expected size {%d}",
			len(arr), size)
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

	index, value := claim.RawSlots()

	for i := range index {
		inputs = append(inputs, index[i].ToInt())
	}
	for i := range value {
		inputs = append(inputs, value[i].ToInt())
	}
	return inputs
}

type nodeAuxValue struct {
	key   *merkletree.Hash
	value *merkletree.Hash
	noAux string
}

func getNodeAuxValue(a *merkletree.NodeAux) nodeAuxValue {

	aux := nodeAuxValue{
		key:   &merkletree.HashZero,
		value: &merkletree.HashZero,
		noAux: "1",
	}

	if a != nil && a.Value != nil && a.Key != nil {
		aux.key = a.Key
		aux.value = a.Value
		aux.noAux = "0"
	}

	return aux
}
