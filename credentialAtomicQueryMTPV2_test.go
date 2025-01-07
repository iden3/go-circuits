package circuits

import (
	"encoding/json"
	"math/big"
	"testing"

	it "github.com/iden3/go-circuits/v2/testing"
	"github.com/stretchr/testify/require"
)

func queryMTPV2Inputs(t testing.TB) AtomicQueryMTPV2Inputs {
	user := it.NewIdentity(t, userPK)
	issuer := it.NewIdentity(t, issuerPK)

	nonce := big.NewInt(0)

	subjectID := user.ID
	nonceSubject := big.NewInt(0)

	claim := it.DefaultUserClaim(t, subjectID)

	issuer.AddClaim(t, claim)

	issuerClaimMtp, _ := issuer.ClaimMTPRaw(t, claim)

	issuerClaimNonRevMtp, _ := issuer.ClaimRevMTPRaw(t, claim)

	return AtomicQueryMTPV2Inputs{
		RequestID:                big.NewInt(23),
		ID:                       &user.ID,
		ProfileNonce:             nonce,
		ClaimSubjectProfileNonce: nonceSubject,
		Claim: ClaimWithMTPProof{
			IssuerID: &issuer.ID,
			Claim:    claim,
			IncProof: MTProof{
				Proof: issuerClaimMtp,
				TreeState: TreeState{
					State:          issuer.State(t),
					ClaimsRoot:     issuer.Clt.Root(),
					RevocationRoot: issuer.Ret.Root(),
					RootOfRoots:    issuer.Rot.Root(),
				},
			},
			NonRevProof: MTProof{
				TreeState: TreeState{
					State:          issuer.State(t),
					ClaimsRoot:     issuer.Clt.Root(),
					RevocationRoot: issuer.Ret.Root(),
					RootOfRoots:    issuer.Rot.Root(),
				},
				Proof: issuerClaimNonRevMtp,
			},
		},
		Query: Query{
			ValueProof: nil,
			Operator:   EQ,
			Values:     it.PrepareIntArray([]*big.Int{big.NewInt(10)}, 64),
			SlotIndex:  2,
		},
		CurrentTimeStamp: timestamp,
	}
}

func TestAttrQueryMTPV2_PrepareInputs(t *testing.T) {
	in := queryMTPV2Inputs(t)
	bytesInputs, err := in.InputsMarshal()
	require.Nil(t, err)

	exp := it.TestData(t, "mtpV2_inputs", string(bytesInputs), *generate)
	t.Log(string(bytesInputs))
	require.JSONEq(t, exp, string(bytesInputs))
}

func TestAttrQueryMTPV2_GetStatesInfo(t *testing.T) {
	in := queryMTPV2Inputs(t)
	statesInfo, err := in.GetStatesInfo()
	require.NoError(t, err)

	bs, err := json.Marshal(statesInfo)
	require.NoError(t, err)

	wantStatesInfo := `{
  "states": [
    {
      "id": "27918766665310231445021466320959318414450284884582375163563581940319453185",
      "state": "19157496396839393206871475267813888069926627705277243727237933406423274512449"
    }
  ],
  "gists": []
}`
	require.JSONEq(t, wantStatesInfo, string(bs))
}

func TestAtomicQueryMTPV2Outputs_CircuitUnmarshal(t *testing.T) {
	out := new(AtomicQueryMTPV2PubSignals)
	err := out.PubSignalsUnmarshal([]byte(`[
 "0",
 "19104853439462320209059061537253618984153217267677512271018416655565783041",
 "23",
 "23528770672049181535970744460798517976688641688582489375761566420828291073",
 "5687720250943511874245715094520098014548846873346473635855112185560372332782",
 "1",
 "5687720250943511874245715094520098014548846873346473635855112185560372332782",
 "1642074362",
 "180410020913331409885634153623124536270",
 "0",
 "0",
 "2",
 "1",
 "10",
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
 "0"
]`))
	require.NoError(t, err)

	expValue, err := PrepareCircuitArrayValues([]*big.Int{big.NewInt(10)}, 64)
	require.NoError(t, err)

	exp := AtomicQueryMTPV2PubSignals{
		RequestID: big.NewInt(23),
		UserID: it.IDFromStr(
			t, "19104853439462320209059061537253618984153217267677512271018416655565783041"),
		IssuerID: it.IDFromStr(t,
			"23528770672049181535970744460798517976688641688582489375761566420828291073"),
		IssuerClaimIdenState: it.MTHashFromStr(t,
			"5687720250943511874245715094520098014548846873346473635855112185560372332782"),
		IssuerClaimNonRevState: it.MTHashFromStr(t, "5687720250943511874245715094520098014548846873346473635855112185560372332782"),
		ClaimSchema:            it.CoreSchemaFromStr(t, "180410020913331409885634153623124536270"),
		SlotIndex:              2,
		Operator:               1,
		Value:                  expValue,
		Timestamp:              int64(1642074362),
		Merklized:              0,
		ClaimPathKey:           big.NewInt(0),
		ClaimPathNotExists:     0,
		IsRevocationChecked:    1,
	}

	jsonOut, err := json.Marshal(out)
	require.NoError(t, err)
	jsonExp, err := json.Marshal(exp)
	require.NoError(t, err)

	require.JSONEq(t, string(jsonExp), string(jsonOut))
}
