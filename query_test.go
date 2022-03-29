package circuits

import (
"math/big"
"testing"

"github.com/stretchr/testify/require"
)

func TestScalarCompare(t *testing.T) {
	type test struct {
		name     string
		x        *big.Int
		y        *big.Int
		operator int
		expected bool
		withErr  bool
	}

	tests := []test{
		{
			name:     "testing $eq operator where x == y",
			x:        big.NewInt(0),
			y:        big.NewInt(0),
			operator: EQ,
			expected: true,
		},
		{
			name:     "testing $eq operator where x != y",
			x:        big.NewInt(10),
			y:        big.NewInt(0),
			operator: EQ,
			expected: false,
		},
		{
			name:     "testing $lt operator where x < y",
			x:        big.NewInt(-1),
			y:        big.NewInt(0),
			operator: LT,
			expected: true,
		},
		{
			name:     "testing $lt operator where x > y",
			x:        big.NewInt(1),
			y:        big.NewInt(0),
			operator: LT,
			expected: false,
		},
		{
			name:     "testing $gt operator where x > y",
			x:        big.NewInt(1),
			y:        big.NewInt(0),
			operator: GT,
			expected: true,
		},
		{
			name:     "testing $gt operator where x < y",
			x:        big.NewInt(0),
			y:        big.NewInt(1),
			operator: GT,
			expected: false,
		},
		{
			name:     "testing unknown operator",
			x:        big.NewInt(0),
			y:        big.NewInt(1),
			operator: 4, // unknown operator.
			expected: false,
			withErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmp := NewScalar(tt.x, tt.y)
			actual, err := cmp.Compare(tt.operator)
			if tt.withErr {
				require.NotNil(t, err)
			} else if err != nil {
				require.NoError(t, err)
			}
			require.Equal(t, tt.expected, actual)
		})
	}
}

func TestVectorCompare(t *testing.T) {
	type test struct {
		name     string
		x        *big.Int
		y        []*big.Int
		operator int
		expected bool
		withErr  bool
	}

	tests := []test{
		{
			name:     "testing $in operator where x EXIST in y",
			x:        big.NewInt(100),
			y:        []*big.Int{big.NewInt(1), big.NewInt(10), big.NewInt(100)},
			operator: IN,
			expected: true,
		},
		{
			name:     "testing $in operator where x NOT EXIST y",
			x:        big.NewInt(1000),
			y:        []*big.Int{big.NewInt(1), big.NewInt(10), big.NewInt(100)},
			operator: IN,
			expected: false,
		},
		{
			name:     "testing $nin operator where x NOT EXIST in y",
			x:        big.NewInt(1000),
			y:        []*big.Int{big.NewInt(1), big.NewInt(10), big.NewInt(100)},
			operator: NIN,
			expected: true,
		},
		{
			name:     "testing $nin operator where x EXIST in y",
			x:        big.NewInt(100),
			y:        []*big.Int{big.NewInt(1), big.NewInt(10), big.NewInt(100)},
			operator: NIN,
			expected: false,
		},
		{
			name:     "testing unknown operator",
			x:        big.NewInt(0),
			y:        []*big.Int{big.NewInt(1), big.NewInt(10), big.NewInt(100)},
			operator: 5, // unknown operator.
			expected: false,
			withErr:  true,
		},
		{
			name:     "empty array for $in. return false",
			x:        big.NewInt(0),
			y:        []*big.Int{},
			operator: IN,
			expected: false,
		},
		{
			name:     "empty array for $nin. return true",
			x:        big.NewInt(0),
			y:        []*big.Int{},
			operator: NIN,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmp := NewVector(tt.x, tt.y)
			actual, err := cmp.Compare(tt.operator)
			if tt.withErr {
				require.NotNil(t, err)
			} else if err != nil {
				require.NoError(t, err)
			}
			require.Equal(t, tt.expected, actual)
		})
	}
}
