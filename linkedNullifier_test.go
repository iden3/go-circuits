package circuits

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	it "github.com/iden3/go-circuits/v2/testing"
	"github.com/stretchr/testify/require"
)

func TestLinkedNullifier_PrepareInputs(t *testing.T) {
	user := it.NewIdentity(t, userPK)
	subjectID := user.ID
	claim := it.DefaultUserClaim(t, subjectID)

	in := LinkedNullifierInputs{
		LinkNonce:                big.NewInt(35346346369657418),
		IssuerClaim:              claim,
		ID:                       &subjectID,
		ClaimSubjectProfileNonce: big.NewInt(21313111),
		VerifierID: it.IDFromStr(
			t, "21929109382993718606847853573861987353620810345503358891473103689157378049"),
		NullifierSessionID: big.NewInt(322215),
	}

	bytesInputs, err := in.InputsMarshal()
	require.Nil(t, err)

	fmt.Println(string(bytesInputs))

	exp := it.TestData(t, "linkedNullifier_inputs", string(bytesInputs), *generate)
	require.JSONEq(t, exp, string(bytesInputs))
}

func TestLinkedNullifierPubSignals_CircuitUnmarshal(t *testing.T) {
	out := new(LinkedNullifierPubSignals)
	err := out.PubSignalsUnmarshal([]byte(
		`[
			"1233342",
			"565429123812",
			"21929109382993718606847853573861987353620810345503358891473103689157378049",
			"2033444042"
		]`))
	require.NoError(t, err)

	exp := LinkedNullifierPubSignals{
		Nullifier: big.NewInt(1233342),
		LinkID:    big.NewInt(565429123812),
		VerifierID: it.IDFromStr(
			t, "21929109382993718606847853573861987353620810345503358891473103689157378049"),
		NullifierSessionID: big.NewInt(2033444042),
	}

	jsonOut, err := json.Marshal(out)
	require.NoError(t, err)
	jsonExp, err := json.Marshal(exp)
	require.NoError(t, err)

	require.JSONEq(t, string(jsonExp), string(jsonOut))
}
