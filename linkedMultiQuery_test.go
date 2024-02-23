package circuits

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	it "github.com/iden3/go-circuits/v2/testing"
	"github.com/stretchr/testify/require"
)

func TestLinkedMultiQueryInputs_PrepareInputs(t *testing.T) {
	user := it.NewIdentity(t, userPK)
	subjectID := user.ID
	claim := it.DefaultUserClaim(t, subjectID)

	queries := make([]*Query, 10)
	queries[0] = &Query{
		ValueProof: nil,
		Operator:   EQ,
		Values:     []*big.Int{big.NewInt(10)},
		SlotIndex:  2,
	}

	queries[1] = &Query{
		ValueProof: nil,
		Operator:   LT,
		Values:     []*big.Int{big.NewInt(133)},
		SlotIndex:  2,
	}

	queries[2] = &Query{
		ValueProof: nil,
		Operator:   LTE,
		Values:     []*big.Int{big.NewInt(555)},
		SlotIndex:  2,
	}

	in := LinkedMultiQueryInputs{
		LinkNonce: big.NewInt(35346346369657418),
		Claim:     claim,
		Query:     queries,
	}

	bytesInputs, err := in.InputsMarshal()
	require.Nil(t, err)

	fmt.Println(string(bytesInputs))

	exp := it.TestData(t, "linkedMultiQuery_inputs", string(bytesInputs), *generate)
	require.JSONEq(t, exp, string(bytesInputs))
}

func TestLinkedMultiQueryPubSignals_CircuitUnmarshal(t *testing.T) {
	out := new(LinkedMultiQueryPubSignals)
	err := out.PubSignalsUnmarshal([]byte(
		`[
			"443",
			"1",
			"1",
			"2",
			"3",
			"4",
			"5",
			"0",
			"0",
			"0",
			"0",
			"0",
			"100",
			"200",
			"300",
			"400",
			"500",
			"0",
			"0",
			"0",
			"0",
			"0",
			"1",
			"1",
			"1",
			"1",
			"1",
			"0",
			"0",
			"0",
			"0",
			"0",
			"1",
			"1",
			"1",
			"1",
			"1",
			"0",
			"0",
			"0",
			"0",
			"0"
		]`))
	require.NoError(t, err)

	operatorOutput := make([]*big.Int, 10)
	circuitQueryHash := make([]*big.Int, 10)
	enabled := make([]bool, 10)
	valueArrSize := make([]int, 10)
	for i := 1; i <= 10; i++ {
		indx := i - 1
		operatorOutput[indx] = big.NewInt((int64(i)))
		circuitQueryHash[indx] = big.NewInt(int64(i * 100))
		enabled[indx] = true
		valueArrSize[indx] = 1
		if i > 5 {
			operatorOutput[indx] = big.NewInt(0)
			circuitQueryHash[indx] = big.NewInt(0)
			enabled[indx] = false
			valueArrSize[indx] = 0
		}
	}

	exp := LinkedMultiQueryPubSignals{
		LinkID:               big.NewInt(443),
		Merklized:            1,
		OperatorOutput:       operatorOutput,
		CircuitQueryHash:     circuitQueryHash,
		Enabled:              enabled,
		ActualValueArraySize: valueArrSize,
	}

	jsonOut, err := json.Marshal(out)
	require.NoError(t, err)
	jsonExp, err := json.Marshal(exp)
	require.NoError(t, err)

	require.JSONEq(t, string(jsonExp), string(jsonOut))
}
