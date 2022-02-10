package circuits

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrepareCircuitArrayValues(t *testing.T) {

	arr := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(2)}

	arr, err := PrepareCircuitArrayValues(arr, 5)

	assert.NoError(t, err)

	exp := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(2), new(big.Int), new(big.Int), new(big.Int)}
	assert.EqualValues(t, exp, arr)

}

func TestPrepareCircuitArrayValuesErr(t *testing.T) {

	arr := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(2)}

	_, err := PrepareCircuitArrayValues(arr, 1)

	assert.Errorf(t, err, "array size 2 is bigger max expected size 1")
}
