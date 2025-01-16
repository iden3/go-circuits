package circuits

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	it "github.com/iden3/go-circuits/v2/testing"
	"github.com/stretchr/testify/require"
)

func createV3Inputs_Sig(t testing.TB) AtomicQueryV3Inputs {
	user := it.NewIdentity(t, userPK)

	issuer := it.NewIdentity(t, issuerPK)

	subjectID := user.ID
	profileNonce := big.NewInt(0)

	nonceSubject := big.NewInt(0)

	claim := it.DefaultUserClaim(t, subjectID)

	// Sig claim
	claimSig := issuer.SignClaim(t, claim)

	issuerClaimNonRevMtp, _ := issuer.ClaimRevMTPRaw(t, claim)

	issuerAuthClaimNonRevMtp, _ := issuer.ClaimRevMTPRaw(t, issuer.AuthClaim)
	issuerAuthClaimMtp, _ := issuer.ClaimMTPRaw(t, issuer.AuthClaim)

	return AtomicQueryV3Inputs{
		RequestID:                big.NewInt(23),
		ID:                       &user.ID,
		ProfileNonce:             profileNonce,
		ClaimSubjectProfileNonce: nonceSubject,
		Claim: ClaimWithSigAndMTPProof{
			IssuerID: &issuer.ID,
			Claim:    claim,
			NonRevProof: MTProof{
				TreeState: TreeState{
					State:          issuer.State(t),
					ClaimsRoot:     issuer.Clt.Root(),
					RevocationRoot: issuer.Ret.Root(),
					RootOfRoots:    issuer.Rot.Root(),
				},
				Proof: issuerClaimNonRevMtp,
			},
			SignatureProof: &BJJSignatureProof{
				Signature:       claimSig,
				IssuerAuthClaim: issuer.AuthClaim,
				IssuerAuthIncProof: MTProof{
					TreeState: TreeState{
						State:          issuer.State(t),
						ClaimsRoot:     issuer.Clt.Root(),
						RevocationRoot: issuer.Ret.Root(),
						RootOfRoots:    issuer.Rot.Root(),
					},
					Proof: issuerAuthClaimMtp,
				},
				IssuerAuthNonRevProof: MTProof{
					TreeState: TreeState{
						State:          issuer.State(t),
						ClaimsRoot:     issuer.Clt.Root(),
						RevocationRoot: issuer.Ret.Root(),
						RootOfRoots:    issuer.Rot.Root(),
					},
					Proof: issuerAuthClaimNonRevMtp,
				},
			},
		},
		Query: Query{
			ValueProof: nil,
			Operator:   EQ,
			Values:     []*big.Int{big.NewInt(10)},
			SlotIndex:  2,
		},
		CurrentTimeStamp: timestamp,
		ProofType:        BJJSignatureProofType,
		LinkNonce:        big.NewInt(0),
		VerifierID: it.IDFromStr(
			t, "21929109382993718606847853573861987353620810345503358891473103689157378049"),
		NullifierSessionID: big.NewInt(32),
	}
}

func TestAttrQueryV3_SigPart_PrepareInputs(t *testing.T) {
	in := createV3Inputs_Sig(t)
	bytesInputs, err := in.InputsMarshal()
	require.Nil(t, err)

	fmt.Println(string(bytesInputs))

	exp := it.TestData(t, "V3_sig_inputs", string(bytesInputs), *generate)
	require.JSONEq(t, exp, string(bytesInputs))
}

func TestAttrQueryV3_SigPart_GetPublicStateInfo(t *testing.T) {
	in := createV3Inputs_Sig(t)
	statesInfo, err := in.GetPublicStatesInfo()
	require.NoError(t, err)

	statesInfoJsonBytes, err := json.Marshal(statesInfo)
	require.NoError(t, err)

	wantStatesInfoJson := `{
  "states":[
    {
      "id":"27918766665310231445021466320959318414450284884582375163563581940319453185",
      "state":"20177832565449474772630743317224985532862797657496372535616634430055981993180"
    }
  ],
  "gists":[]
}`

	require.JSONEq(t, wantStatesInfoJson, string(statesInfoJsonBytes))
}

func TestAttrQueryV3_MTPPart_PrepareInputs(t *testing.T) {

	user := it.NewIdentity(t, userPK)
	issuer := it.NewIdentity(t, issuerPK)

	nonce := big.NewInt(0)

	subjectID := user.ID
	nonceSubject := big.NewInt(0)

	claim := it.DefaultUserClaim(t, subjectID)

	issuer.AddClaim(t, claim)

	issuerClaimMtp, _ := issuer.ClaimMTPRaw(t, claim)

	issuerClaimNonRevMtp, _ := issuer.ClaimRevMTPRaw(t, claim)

	in := AtomicQueryV3Inputs{
		RequestID:                big.NewInt(23),
		ID:                       &user.ID,
		ProfileNonce:             nonce,
		ClaimSubjectProfileNonce: nonceSubject,
		Claim: ClaimWithSigAndMTPProof{
			IssuerID: &issuer.ID,
			Claim:    claim,
			IncProof: &MTProof{
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
			Values:     []*big.Int{big.NewInt(10)},
			SlotIndex:  2,
		},
		CurrentTimeStamp: timestamp,
		ProofType:        Iden3SparseMerkleTreeProofType,
		LinkNonce:        big.NewInt(0),
		VerifierID: it.IDFromStr(
			t, "21929109382993718606847853573861987353620810345503358891473103689157378049"),
		NullifierSessionID: big.NewInt(32),
	}

	bytesInputs, err := in.InputsMarshal()
	require.Nil(t, err)

	exp := it.TestData(t, "V3_mtp_inputs", string(bytesInputs), *generate)
	t.Log(string(bytesInputs))
	require.JSONEq(t, exp, string(bytesInputs))

}

func TestAttrQueryV3_MTPPart_Noop_PrepareInputs(t *testing.T) {
	user := it.NewIdentity(t, userPK)
	issuer := it.NewIdentity(t, issuerPK)

	nonce := big.NewInt(0)

	subjectID := user.ID
	nonceSubject := big.NewInt(0)

	claim := it.DefaultUserClaim(t, subjectID)

	issuer.AddClaim(t, claim)

	issuerClaimMtp, _ := issuer.ClaimMTPRaw(t, claim)

	issuerClaimNonRevMtp, _ := issuer.ClaimRevMTPRaw(t, claim)

	in := AtomicQueryV3Inputs{
		RequestID:                big.NewInt(23),
		ID:                       &user.ID,
		ProfileNonce:             nonce,
		ClaimSubjectProfileNonce: nonceSubject,
		Claim: ClaimWithSigAndMTPProof{
			IssuerID: &issuer.ID,
			Claim:    claim,
			IncProof: &MTProof{
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
			Operator:   NOOP,
			Values:     nil,
			SlotIndex:  2,
		},
		CurrentTimeStamp: timestamp,
		ProofType:        Iden3SparseMerkleTreeProofType,
		LinkNonce:        big.NewInt(0),
		VerifierID: it.IDFromStr(
			t, "21929109382993718606847853573861987353620810345503358891473103689157378049"),
		NullifierSessionID: big.NewInt(32),
	}

	bytesInputs, err := in.InputsMarshal()
	require.Nil(t, err)

	exp := it.TestData(t, "V3_mtp_noop_inputs", string(bytesInputs), *generate)
	require.JSONEq(t, exp, string(bytesInputs))

}

func TestAtomicQueryV3Outputs_Sig_CircuitUnmarshal(t *testing.T) {
	out := new(AtomicQueryV3PubSignals)
	err := out.PubSignalsUnmarshal([]byte(
		`[
 "0",
 "23148936466334350744548790012294489365207440754509988986684797708370051073",
 "2943483356559152311923412925436024635269538717812859789851139200242297094",
 "0",
 "0",
 "0",
 "0",
 "23",
 "21933750065545691586450392143787330185992517860945727248803138245838110721",
 "1",
 "2943483356559152311923412925436024635269538717812859789851139200242297094",
 "1642074362",
 "180410020913331409885634153623124536270",
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
 "0",
 "1",
 "21929109382993718606847853573861987353620810345503358891473103689157378049",
 "32"
]`))
	require.NoError(t, err)

	expValue, err := PrepareCircuitArrayValues([]*big.Int{big.NewInt(10)}, 64)
	require.NoError(t, err)

	exp := AtomicQueryV3PubSignals{
		RequestID: big.NewInt(23),
		UserID: it.IDFromStr(t,
			"23148936466334350744548790012294489365207440754509988986684797708370051073"),
		IssuerID: it.IDFromStr(t,
			"21933750065545691586450392143787330185992517860945727248803138245838110721"),
		IssuerState: it.MTHashFromStr(t,
			"2943483356559152311923412925436024635269538717812859789851139200242297094"),
		IssuerClaimNonRevState: it.MTHashFromStr(t,
			"2943483356559152311923412925436024635269538717812859789851139200242297094"),
		ClaimSchema: it.CoreSchemaFromStr(t,
			"180410020913331409885634153623124536270"),
		SlotIndex:            2,
		Operator:             1,
		Value:                expValue,
		ActualValueArraySize: 1,
		Timestamp:            int64(1642074362),
		Merklized:            0,
		ClaimPathKey:         big.NewInt(0),
		IsRevocationChecked:  1,
		ProofType:            0,
		LinkID:               big.NewInt(0),
		Nullifier:            big.NewInt(0),
		OperatorOutput:       big.NewInt(0),
		VerifierID: it.IDFromStr(
			t, "21929109382993718606847853573861987353620810345503358891473103689157378049"),
		NullifierSessionID: big.NewInt(32),
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
				ID:    idFromInt("21933750065545691586450392143787330185992517860945727248803138245838110721"),
				State: hashFromInt("2943483356559152311923412925436024635269538717812859789851139200242297094"),
			},
		},
		Gists: []Gist{},
	}
	j, err := json.Marshal(statesInfo)
	require.NoError(t, err)
	require.Equal(t, wantStatesInfo, statesInfo, string(j))
}

func TestAtomicQueryV3Outputs_MTP_CircuitUnmarshal(t *testing.T) {
	out := new(AtomicQueryV3PubSignals)
	err := out.PubSignalsUnmarshal([]byte(
		`[
 "0",
 "19104853439462320209059061537253618984153217267677512271018416655565783041",
 "5687720250943511874245715094520098014548846873346473635855112185560372332782",
 "0",
 "0",
 "0",
 "1",
 "23",
 "23528770672049181535970744460798517976688641688582489375761566420828291073",
 "1",
 "5687720250943511874245715094520098014548846873346473635855112185560372332782",
 "1642074362",
 "180410020913331409885634153623124536270",
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
 "0",
 "1",
 "21929109382993718606847853573861987353620810345503358891473103689157378049",
 "32"
]`))
	require.NoError(t, err)

	expValue, err := PrepareCircuitArrayValues([]*big.Int{big.NewInt(10)}, 64)
	require.NoError(t, err)

	exp := AtomicQueryV3PubSignals{
		RequestID: big.NewInt(23),
		UserID: it.IDFromStr(
			t, "19104853439462320209059061537253618984153217267677512271018416655565783041"),
		IssuerID: it.IDFromStr(t,
			"23528770672049181535970744460798517976688641688582489375761566420828291073"),
		IssuerState: it.MTHashFromStr(t,
			"5687720250943511874245715094520098014548846873346473635855112185560372332782"),
		IssuerClaimNonRevState: it.MTHashFromStr(t,
			"5687720250943511874245715094520098014548846873346473635855112185560372332782"),
		ClaimSchema: it.CoreSchemaFromStr(t,
			"180410020913331409885634153623124536270"),
		SlotIndex:            2,
		Operator:             1,
		Value:                expValue,
		ActualValueArraySize: 1,
		Timestamp:            int64(1642074362),
		Merklized:            0,
		ClaimPathKey:         big.NewInt(0),
		IsRevocationChecked:  1,
		ProofType:            1,
		LinkID:               big.NewInt(0),
		Nullifier:            big.NewInt(0),
		OperatorOutput:       big.NewInt(0),
		VerifierID: it.IDFromStr(
			t, "21929109382993718606847853573861987353620810345503358891473103689157378049"),
		NullifierSessionID: big.NewInt(32),
	}

	jsonOut, err := json.Marshal(out)
	require.NoError(t, err)
	jsonExp, err := json.Marshal(exp)
	require.NoError(t, err)

	require.JSONEq(t, string(jsonExp), string(jsonOut))
}
