package circuits

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestPoseidonHash_64input(t *testing.T) {
	arr := make([]*big.Int, 64)
	for i := 0; i < 64; i++ {
		arr[i] = big.NewInt(0)
	}
	h1, err := poseidonHash(arr)
	exp, ok := new(big.Int).SetString("727338310353795144219993768420910033473938536894650379536715977254833201346", 10)
	require.Empty(t, err)
	require.True(t, ok)
	assert.Equal(t, h1, exp)

	for i := 0; i < 64; i++ {
		arr[i] = big.NewInt(int64(i + 1))
	}
	h2, err := poseidonHash(arr)
	exp, ok = new(big.Int).SetString("9206504708748250872960725447878206077072019695495427485684343849164309826975", 10)
	require.True(t, ok)
	require.Empty(t, err)
	assert.Equal(t, h2, exp)

	for i := 0; i < 64; i++ {
		arr[i] = big.NewInt(int64(64 - i))
	}
	h3, err := poseidonHash(arr)
	exp, ok = new(big.Int).SetString("11790321463525137746903439564431765868870258693422117265865753765715743495357", 10)
	require.True(t, ok)
	require.Empty(t, err)
	assert.Equal(t, h3, exp)
}
