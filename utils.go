package circuits

import (
	"fmt"
	"math/big"
	"reflect"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql/v2"
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

// CircomSiblingsFromSiblings returns the full siblings compatible with circom
func CircomSiblings(proof *merkletree.Proof, levels int) []*merkletree.Hash {
	siblings := proof.AllSiblings()
	// Add the rest of empty levels to the siblings
	for i := len(siblings); i < levels; i++ {
		siblings = append(siblings, &merkletree.HashZero)
	}
	return siblings
}

func HashToStr(siblings []*merkletree.Hash) []string {
	siblingsStr := make([]string, len(siblings))
	for i, sibling := range siblings {
		siblingsStr[i] = sibling.BigInt().String()
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

func bigIntArrayToStringArray(array []*big.Int) []string {
	res := make([]string, 0)
	for i := range array {
		res = append(res, array[i].String())
	}
	return res
}

type NodeAuxValue struct {
	key   *merkletree.Hash
	value *merkletree.Hash
	noAux string
}

func GetNodeAuxValue(p *merkletree.Proof) NodeAuxValue {

	// proof of inclusion
	if p.Existence {
		return NodeAuxValue{
			key:   &merkletree.HashZero,
			value: &merkletree.HashZero,
			noAux: "0",
		}
	}

	// proof of non-inclusion (NodeAux exists)
	if p.NodeAux != nil && p.NodeAux.Value != nil && p.NodeAux.Key != nil {
		return NodeAuxValue{
			key:   p.NodeAux.Key,
			value: p.NodeAux.Value,
			noAux: "0",
		}
	}
	// proof of non-inclusion (NodeAux does not exist)
	return NodeAuxValue{
		key:   &merkletree.HashZero,
		value: &merkletree.HashZero,
		noAux: "1",
	}
}

func idFromIntStr(s string) (*core.ID, error) {
	strID, b := new(big.Int).SetString(s, 10)
	if !b {
		return nil, fmt.Errorf("can not convert {%s} to ID", s)
	}
	id, err := core.IDFromInt(strID)
	if err != nil {
		return nil, err
	}

	return &id, nil
}

func toMap(in interface{}) map[string]interface{} {
	out := make(map[string]interface{})

	value := reflect.ValueOf(in)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}

	typ := value.Type()
	for i := 0; i < value.NumField(); i++ {
		fi := typ.Field(i)
		if jsonTag := fi.Tag.Get("json"); jsonTag != "" {
			out[jsonTag] = value.Field(i).Interface()
		}
	}
	return out
}

func existenceToInt(b bool) int {
	if b {
		return 0
	}
	return 1
}
