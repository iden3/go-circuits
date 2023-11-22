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
			name:     "testing $in should fail",
			x:        big.NewInt(0),
			y:        big.NewInt(1),
			operator: IN,
			expected: false,
			withErr:  true,
		},
		{
			name:     "testing $nin should faile",
			x:        big.NewInt(0),
			y:        big.NewInt(1),
			operator: NIN,
			expected: false,
			withErr:  true,
		},
		{
			name:     "testing $ne operator where x == y",
			x:        big.NewInt(0),
			y:        big.NewInt(0),
			operator: NE,
			expected: false,
		},
		{
			name:     "testing $ne operator where x != y",
			x:        big.NewInt(10),
			y:        big.NewInt(0),
			operator: NE,
			expected: true,
		},
		{
			name:     "testing $lte operator where x == y",
			x:        big.NewInt(0),
			y:        big.NewInt(0),
			operator: LTE,
			expected: true,
		},
		{
			name:     "testing $lte operator where x < y",
			x:        big.NewInt(0),
			y:        big.NewInt(1),
			operator: LTE,
			expected: true,
		},
		{
			name:     "testing $lte operator where x > y",
			x:        big.NewInt(2),
			y:        big.NewInt(1),
			operator: LTE,
			expected: false,
		},
		{
			name:     "testing $gte operator where x == y",
			x:        big.NewInt(0),
			y:        big.NewInt(0),
			operator: GTE,
			expected: true,
		},
		{
			name:     "testing $gte operator where x < y",
			x:        big.NewInt(0),
			y:        big.NewInt(1),
			operator: GTE,
			expected: false,
		},
		{
			name:     "testing $gte operator where x > y",
			x:        big.NewInt(2),
			y:        big.NewInt(1),
			operator: GTE,
			expected: true,
		},
		{
			name:     "testing unknown operator should fail",
			x:        big.NewInt(0),
			y:        big.NewInt(1),
			operator: 10, // unknown operator.
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
			operator: 10, // unknown operator.
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
		{
			name:     "one value array for $between. return false",
			x:        big.NewInt(0),
			y:        []*big.Int{big.NewInt(1)},
			operator: BETWEEN,
			expected: false,
		},
		{
			name:     "testing $between operator where x in between range.",
			x:        big.NewInt(2),
			y:        []*big.Int{big.NewInt(1), big.NewInt(3)},
			operator: BETWEEN,
			expected: true,
		},
		{
			name:     "testing $between operator where x not in between range.",
			x:        big.NewInt(0),
			y:        []*big.Int{big.NewInt(1), big.NewInt(3)},
			operator: BETWEEN,
			expected: false,
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
