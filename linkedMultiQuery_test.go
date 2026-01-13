package circuits

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
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

// test if query slice length is less than LinkedMultiQueryLength
func TestLinkedMultiQueryInputs_PrepareInputs_Ln(t *testing.T) {
	user := it.NewIdentity(t, userPK)
	subjectID := user.ID
	claim := it.DefaultUserClaim(t, subjectID)
	in := LinkedMultiQueryInputs{
		LinkNonce: big.NewInt(35346346369657418),
		Claim:     claim,
	}
	in.Query = append(in.Query,
		&Query{
			ValueProof: nil,
			Operator:   EQ,
			Values:     []*big.Int{big.NewInt(10)},
			SlotIndex:  2,
		},
		&Query{
			ValueProof: nil,
			Operator:   LT,
			Values:     []*big.Int{big.NewInt(133)},
			SlotIndex:  2,
		},
		&Query{
			ValueProof: nil,
			Operator:   LTE,
			Values:     []*big.Int{big.NewInt(555)},
			SlotIndex:  2,
		},
	)

	bytesInputs, err := in.InputsMarshal()
	require.NoError(t, err)

	exp := it.TestData(t, "linkedMultiQuery_inputs", string(bytesInputs), *generate)
	require.JSONEq(t, exp, string(bytesInputs))
}

func TestLinkedMultiQueryInputs_PrepareInputs_Error(t *testing.T) {
	user := it.NewIdentity(t, userPK)
	subjectID := user.ID
	claim := it.DefaultUserClaim(t, subjectID)
	in := LinkedMultiQueryInputs{
		//LinkNonce: big.NewInt(35346346369657418),
		//Claim:     claim,
	}
	_, err := in.InputsMarshal()
	require.EqualError(t, err, "empty link nonce")

	in.LinkNonce = big.NewInt(35346346369657418)
	_, err = in.InputsMarshal()
	require.EqualError(t, err, "empty claim")

	in.Claim = claim
	_, err = in.InputsMarshal()
	require.EqualError(t, err, "empty queries")

	in.Query = append(in.Query,
		&Query{
			ValueProof: nil,
			Operator:   EQ,
			Values:     []*big.Int{big.NewInt(10)},
			SlotIndex:  2,
		},
		&Query{
			ValueProof: nil,
			Operator:   LT,
			Values:     []*big.Int{big.NewInt(133)},
			SlotIndex:  2,
		},
		&Query{
			ValueProof: nil,
			Operator:   LTE,
			Values:     []*big.Int{big.NewInt(555)},
			SlotIndex:  2,
		},
	)

	bytesInputs, err := in.InputsMarshal()
	require.NoError(t, err)

	exp := it.TestData(t, "linkedMultiQuery_inputs", string(bytesInputs), *generate)
	require.JSONEq(t, exp, string(bytesInputs))
}

func TestLinkedMultiQueryPubSignals_CircuitUnmarshal(t *testing.T) {
	outs := map[int][]string{
		3: {
			"11587660915189382633314527098062647837126752531205087409048618395969242885016",
			"0",
			"0",
			"0",
			"0",
			"9458417390459068300741864705379630488534450155484493792325907355745201035449",
			"10864698602219511323750171112812294233505545576258213541845435681330532958075",
			"5365138871441717895206514697230448654236988235704905467582456422975445794731",
		},
		5: {
			"20336008450539684768013573494073798243349685857640613070314041678185349736439",
			"1",
			"0",
			"0",
			"0",
			"0",
			"0",
			"3326382892536126749483088946048689911243394580824744244053752370464747528203",
			"9907132056133666096701539062450765284880813426582692863734448403438789333698",
			"13362042977965885903820557513534065802896288300017199700677633721405805677442",
			"13362042977965885903820557513534065802896288300017199700677633721405805677442",
			"13362042977965885903820557513534065802896288300017199700677633721405805677442",
		},
		10: {
			"11587660915189382633314527098062647837126752531205087409048618395969242885016",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"9458417390459068300741864705379630488534450155484493792325907355745201035449",
			"10864698602219511323750171112812294233505545576258213541845435681330532958075",
			"5365138871441717895206514697230448654236988235704905467582456422975445794731",
			"6552534440600411908158043655342660449140617599402291128616319085888035740680",
			"6552534440600411908158043655342660449140617599402291128616319085888035740680",
			"6552534440600411908158043655342660449140617599402291128616319085888035740680",
			"6552534440600411908158043655342660449140617599402291128616319085888035740680",
			"6552534440600411908158043655342660449140617599402291128616319085888035740680",
			"6552534440600411908158043655342660449140617599402291128616319085888035740680",
			"6552534440600411908158043655342660449140617599402291128616319085888035740680",
		},
	}

	for queriesCount, out := range outs {
		t.Run(fmt.Sprintf("LinkedMultiQueryPubSignals_CircuitUnmarshal_%d", queriesCount), func(t *testing.T) {
			ao := &LinkedMultiQueryPubSignals{
				QueryLength: queriesCount,
			}

			jsonData, err := json.Marshal(out)
			require.NoError(t, err)

			err = ao.PubSignalsUnmarshal(jsonData)
			require.NoError(t, err)

			// Check linkID (out[0])
			expectedLinkID, ok := big.NewInt(0).SetString(out[0], 10)
			require.True(t, ok, "failed to parse linkID")
			require.Equal(t, expectedLinkID, ao.LinkID)

			// Check merklized (out[1])
			expectedMerklized, err := strconv.Atoi(out[1])
			require.NoError(t, err)
			require.Equal(t, expectedMerklized, ao.Merklized)

			// Check operatorOutput (out.slice(2, 2 + queriesCount))
			expectedOperatorOutput := make([]*big.Int, queriesCount)
			for i := 0; i < queriesCount; i++ {
				val, ok := big.NewInt(0).SetString(out[2+i], 10)
				require.True(t, ok, fmt.Sprintf("failed to parse operatorOutput[%d]", i))
				expectedOperatorOutput[i] = val
			}
			require.Equal(t, expectedOperatorOutput, ao.OperatorOutput)

			// Check circuitQueryHash (out.slice(2 + queriesCount, 2 + queriesCount * 2))
			expectedCircuitQueryHash := make([]*big.Int, queriesCount)
			for i := 0; i < queriesCount; i++ {
				val, ok := big.NewInt(0).SetString(out[2+queriesCount+i], 10)
				require.True(t, ok, fmt.Sprintf("failed to parse circuitQueryHash[%d]", i))
				expectedCircuitQueryHash[i] = val
			}
			require.Equal(t, expectedCircuitQueryHash, ao.CircuitQueryHash)
		})
	}
}
