package circuits

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	it "github.com/iden3/go-circuits/testing"
	"github.com/iden3/go-schema-processor/merklize"
	"github.com/stretchr/testify/require"
)

func TestAttrQueryMTPV2_PrepareInputs(t *testing.T) {

	user, err := it.NewIdentity(userPK)
	require.NoError(t, err)
	nonce := big.NewInt(0)

	issuer, err := it.NewIdentity(issuerPK)
	require.NoError(t, err)

	subjectID := user.ID
	nonceSubject := big.NewInt(0)

	mz, claim, err := it.DefaultJSONUserClaim(subjectID)
	require.NoError(t, err)

	path, err := merklize.NewPath(
		"https://www.w3.org/2018/credentials#credentialSubject",
		"https://w3id.org/citizenship#residentSince")
	require.NoError(t, err)

	jsonP, value, err := mz.Proof(context.Background(), path)
	require.NoError(t, err)

	valueKey, err := value.MtEntry()
	require.NoError(t, err)

	values := it.PrepareStrArray([]string{valueKey.String()}, 64)
	//string array to big.Int array
	valuesBigInt := make([]*big.Int, len(values))
	for i, v := range values {
		in, b := new(big.Int).SetString(v, 10)
		require.True(t, b)
		valuesBigInt[i] = in

	}

	issuer.AddClaim(t, claim)

	issuerClaimMtp, _, err := issuer.ClaimMTPRaw(claim)
	require.NoError(t, err)

	issuerClaimNonRevMtpRaw, _, err := issuer.ClaimRevMTPRaw(claim)
	require.NoError(t, err)

	in := AtomicQueryMTPV2Inputs{
		RequestID:                big.NewInt(23),
		ID:                       &user.ID,
		Nonce:                    nonce,
		ClaimSubjectProfileNonce: nonceSubject,
		Claim: ClaimWithMTPProof{
			IssuerID: &issuer.ID,
			Claim:    claim,
			IncProof: MTProof{
				Proof: issuerClaimMtp,
				TreeState: TreeState{
					State:          issuer.State(),
					ClaimsRoot:     issuer.Clt.Root(),
					RevocationRoot: issuer.Ret.Root(),
					RootOfRoots:    issuer.Rot.Root(),
				},
			},
			NonRevProof: MTProof{
				TreeState: TreeState{
					State:          issuer.State(),
					ClaimsRoot:     issuer.Clt.Root(),
					RevocationRoot: issuer.Ret.Root(),
					RootOfRoots:    issuer.Rot.Root(),
				},
				Proof: issuerClaimNonRevMtpRaw,
			},
		},
		Query: Query{
			ValueProof: &ValueProof{
				Path:  path,
				Value: valueKey,
				MTP:   jsonP,
			},
			Operator:  EQ,
			Values:    valuesBigInt,
			SlotIndex: 2,
		},
		CurrentTimeStamp: timestamp,
	}

	bytesInputs, err := in.InputsMarshal()
	require.Nil(t, err)

	exp := it.TestData(t, "AttrQueryMTPV2_inputs", string(bytesInputs), *generate)
	t.Log(string(bytesInputs))
	require.JSONEq(t, exp, string(bytesInputs))

}

func TestAtomicQueryMTPV2Outputs_CircuitUnmarshal(t *testing.T) {
	out := new(AtomicQueryMTPV2PubSignals)
	err := out.PubSignalsUnmarshal([]byte(
		`[
 "0",
 "19104853439462320209059061537253618984153217267677512271018416655565783041",
 "23",
 "23528770672049181535970744460798517976688641688582489375761566420828291073",
 "5687720250943511874245715094520098014548846873346473635855112185560372332782",
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
	}

	jsonOut, err := json.Marshal(out)
	require.NoError(t, err)
	jsonExp, err := json.Marshal(exp)
	require.NoError(t, err)

	require.JSONEq(t, string(jsonExp), string(jsonOut))
}
