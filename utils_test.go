package circuits

import (
	"fmt"
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

func Test_PoseidonValueHash(t *testing.T) {

	getBigintArray := func(l int, f func(idx int) int) []*big.Int {
		result := make([]*big.Int, l)
		for i := 0; i < l; i++ {
			result[i] = big.NewInt(int64(f(i)))
		}
		return result
	}

	testCases := []struct {
		name     string
		input    []*big.Int
		expected string
	}{
		{
			name: "PoseidonValueHash all zeros",
			input: getBigintArray(64, func(idx int) int {
				return 0
			}),
			expected: "7368935780301629035733097554153370898490964345621267223639562510928947240459",
		},
		{
			name: "PoseidonValueHash 63 idx + 1",
			input: getBigintArray(63, func(idx int) int {
				return idx + 1
			}),
			expected: "3027148895471770401984833121350831002277377476084832804937751928355120074994",
		},
		{
			name: "PoseidonValueHash 60 items",
			input: getBigintArray(60, func(idx int) int {
				return 60 - idx
			}),
			expected: "13254546416358473313457812414193018870743005197521155619424967381510427667259",
		},
		{
			name: "PoseidonValueHash 5 vals",
			input: getBigintArray(5, func(idx int) int {
				return idx + 1
			}),
			expected: "6186895146109816025093019628248576250523388957868658785525378722128520330607",
		},
		{
			name: "PoseidonValueHash 1 value",
			input: getBigintArray(1, func(idx int) int {
				return 0
			}),
			expected: "14408838593220040598588012778523101864903887657864399481915450526643617223637",
		},
		{
			name: "PoseidonValueHash 6 vals",
			input: getBigintArray(6, func(idx int) int {
				return idx + 1
			}),
			expected: "20400040500897583745843009878988256314335038853985262692600694741116813247201",
		},
		{
			name: "PoseidonValueHash 16 vals",
			input: getBigintArray(16, func(idx int) int {
				return idx + 1
			}),
			expected: "5605330091169856132381694679994923791994681609858984566508182442210285386845",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			poseidonValueHash, err := PoseidonHashValue(tc.input)
			require.NoError(t, err)
			fmt.Println("PoseidonValueHash:", poseidonValueHash.String())
			require.Equal(t, tc.expected, poseidonValueHash.String())
		})
	}
}
