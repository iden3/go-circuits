package circuits

import (
	"encoding/json"
	"math/big"
	"testing"

	it "github.com/iden3/go-circuits/v2/testing"
	"github.com/stretchr/testify/require"
)

func TestAtomicQueryV3UniversalOutputsCircuitUnmarshal(t *testing.T) {
	out := new(AtomicQueryV3UniversalPubSignals)
	err := out.PubSignalsUnmarshal([]byte(
		`[
 "22547885961380641656890522948966953732133055194604876766672713705832321537",
 "19807516177872076324802462820131296019241193150904977369555677697559725431535",
 "4575193482325603893215142619623809490166676718476384166883471046672443708329",
 "0",
 "16321897390546343714174413659582254042752392145999028505097676701328201511519",
 "0",
 "2",
 "23",
 "22057981499787921734624217749308316644136637822444794206796063681866502657",
 "1",
 "4575193482325603893215142619623809490166676718476384166883471046672443708329",
 "1642074362",
 "180410020913331409885634153623124536270",
 "0",
 "2",
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
 "21929109382993718606847853573861987353620810345503358891473103689157378049",
 "123"
]`))
	require.NoError(t, err)

	expValue, err := PrepareCircuitArrayValues([]*big.Int{}, 64)
	require.NoError(t, err)

	circuitQueryHash, ok := big.NewInt(0).SetString("19807516177872076324802462820131296019241193150904977369555677697559725431535", 10)
	require.True(t, ok)

	nullifier, ok := big.NewInt(0).SetString("16321897390546343714174413659582254042752392145999028505097676701328201511519", 10)
	require.True(t, ok)

	exp := AtomicQueryV3UniversalPubSignals{
		RequestID:        big.NewInt(23),
		CircuitQueryHash: circuitQueryHash,
		UserID: it.IDFromStr(t,
			"22547885961380641656890522948966953732133055194604876766672713705832321537"),
		IssuerID: it.IDFromStr(t,
			"22057981499787921734624217749308316644136637822444794206796063681866502657"),
		IssuerState: it.MTHashFromStr(t,
			"4575193482325603893215142619623809490166676718476384166883471046672443708329"),
		IssuerClaimNonRevState: it.MTHashFromStr(t,
			"4575193482325603893215142619623809490166676718476384166883471046672443708329"),
		ClaimSchema: it.CoreSchemaFromStr(t,
			"180410020913331409885634153623124536270"),
		SlotIndex:            2,
		Operator:             0,
		Value:                expValue,
		ActualValueArraySize: 0,
		Timestamp:            int64(1642074362),
		Merklized:            0,
		ClaimPathKey:         big.NewInt(0),
		IsRevocationChecked:  1,
		ProofType:            2,
		LinkID:               big.NewInt(0),
		Nullifier:            nullifier,
		OperatorOutput:       big.NewInt(0),
		VerifierID: it.IDFromStr(
			t, "21929109382993718606847853573861987353620810345503358891473103689157378049"),
		NullifierSessionID: big.NewInt(123),
	}

	jsonOut, err := json.Marshal(out)
	require.NoError(t, err)
	jsonExp, err := json.Marshal(exp)
	require.NoError(t, err)

	require.JSONEq(t, string(jsonExp), string(jsonOut))

	statesInfo, err := exp.GetStatesInfo()
	require.NoError(t, err)
	wantStatesInfo := StatesInfo{
		States: []State{
			{
				ID:    idFromInt("22057981499787921734624217749308316644136637822444794206796063681866502657"),
				State: hashFromInt("4575193482325603893215142619623809490166676718476384166883471046672443708329"),
			},
		},
		Gists: []Gist{},
	}
	j, err := json.Marshal(statesInfo)
	require.NoError(t, err)
	require.Equal(t, wantStatesInfo, statesInfo, string(j))
}
