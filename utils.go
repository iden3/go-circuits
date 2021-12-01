package circuits

import (
	"math/big"

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
