package circuits

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestPoseidonExtendedHash(t *testing.T) {
	zeros := make([]*big.Int, 64)
	for i := range zeros {
		zeros[i] = big.NewInt(0)
	}
	sequence := make([]*big.Int, 63)
	for i := range sequence {
		sequence[i] = big.NewInt(int64(i + 1))
	}
	reverseSequence := make([]*big.Int, 60)
	for i := range reverseSequence {
		reverseSequence[i] = big.NewInt(int64(60 - i))
	}

	testCases := [][]*big.Int{
		zeros,
		sequence,
		reverseSequence,
		{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5)},
		{big.NewInt(0)},
		{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5), big.NewInt(6)},
	}

	testResults := []string{
		"7368935780301629035733097554153370898490964345621267223639562510928947240459",
		"5141441971348023348086244244216563379825719214260560525236342102655139861412",
		"1980406908386847376697137710198826655972108629440197428494707119108499632713",
		"2579592068985894564663884204285667087640059297900666937160965942401359072100",
		"14408838593220040598588012778523101864903887657864399481915450526643617223637",
		"11520133791077739462983963458665556954298550456396705311618752731525149020132",
	}

	for i, testCase := range testCases {
		result, err := PoseidonHash(testCase)
		require.NoError(t, err)
		fmt.Println(result.String())
		assert.Equal(t, testResults[i], result.String())
	}
}
