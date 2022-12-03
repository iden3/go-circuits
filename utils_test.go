package circuits

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrepareCircuitArrayValues(t *testing.T) {

	arr := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(2)}

	arr, err := PrepareCircuitArrayValues(arr, 5)

	require.NoError(t, err)

	exp := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(2), new(big.Int), new(big.Int), new(big.Int)}
	require.EqualValues(t, exp, arr)

}

func TestPrepareCircuitArrayValuesErr(t *testing.T) {

	arr := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(2)}

	_, err := PrepareCircuitArrayValues(arr, 1)

	require.Errorf(t, err, "array size 2 is bigger max expected size 1")
}

func Test_existenceToInt(t *testing.T) {
	require.True(t, existenceToInt(true) == 0)
	require.True(t, existenceToInt(false) == 1)
}
