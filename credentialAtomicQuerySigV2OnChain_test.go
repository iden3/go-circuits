package circuits

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	it "github.com/iden3/go-circuits/v2/testing"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/require"
)

func querySigV2OnChainInputs(t testing.TB) AtomicQuerySigV2OnChainInputs {
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

	// generate global tree
	gTree := it.GISTTree(context.Background())

	err := gTree.Add(context.Background(), issuer.ID.BigInt(), issuer.State(t).BigInt())
	require.NoError(t, err)

	// prepare inputs
	globalProof, _, err := gTree.GenerateProof(context.Background(), user.ID.BigInt(), nil)
	require.NoError(t, err)
	authClaimIncMTP, _ := user.ClaimMTPRaw(t, user.AuthClaim)

	authClaimNonRevMTP, _ := user.ClaimRevMTPRaw(t, user.AuthClaim)
	require.NoError(t, err)
	challenge := big.NewInt(10)
	signature, err := user.SignBBJJ(challenge.Bytes())
	require.NoError(t, err)

	return AtomicQuerySigV2OnChainInputs{
		RequestID:                big.NewInt(23),
		ID:                       &user.ID,
		ProfileNonce:             profileNonce,
		ClaimSubjectProfileNonce: nonceSubject,
		Claim: ClaimWithSigProof{
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
			SignatureProof: BJJSignatureProof{
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
			Values:     it.PrepareIntArray([]*big.Int{big.NewInt(10)}, 64),
			SlotIndex:  2,
		},
		CurrentTimeStamp:   timestamp,
		AuthClaim:          user.AuthClaim,
		AuthClaimIncMtp:    authClaimIncMTP,
		AuthClaimNonRevMtp: authClaimNonRevMTP,
		TreeState:          GetTreeState(t, user),
		GISTProof: GISTProof{
			Root:  gTree.Root(),
			Proof: globalProof,
		},
		Signature: signature,
		Challenge: challenge,
	}
}

func TestAttrQuerySigV2OnChain_PrepareInputs(t *testing.T) {
	in := querySigV2OnChainInputs(t)
	bytesInputs, err := in.InputsMarshal()
	require.Nil(t, err)

	exp := it.TestData(t, "sigV2OnChain_inputs", string(bytesInputs), *generate)
	require.JSONEq(t, exp, string(bytesInputs))
}

func TestAttrQuerySigV2OnChain_GetPublicStatesInfo(t *testing.T) {
	in := querySigV2OnChainInputs(t)
	statesInfo, err := in.GetPublicStatesInfo()
	require.NoError(t, err)

	bs, err := json.Marshal(statesInfo)
	require.NoError(t, err)

	wantStatesInfo := `{
  "states": [
    {
      "id": "27918766665310231445021466320959318414450284884582375163563581940319453185",
      "state": "20177832565449474772630743317224985532862797657496372535616634430055981993180"
    }
  ],
  "gists": [
    {
      "id": "26109404700696283154998654512117952420503675471097392618762221546565140481",
      "root": "11098939821764568131087645431296528907277253709936443029379587475821759259406"
    }
  ]
}`
	require.JSONEq(t, wantStatesInfo, string(bs))
}

func TestAtomicQuerySigV2OnChainOutputs_CircuitUnmarshal(t *testing.T) {
	out := new(AtomicQuerySigV2OnChainPubSignals)
	err := out.PubSignalsUnmarshal([]byte(
		`[
 "0",
 "26109404700696283154998654512117952420503675471097392618762221546565140481",
 "7002038488948284767652984010448061038733120594540539539730565455904340350321",
 "20177832565449474772630743317224985532862797657496372535616634430055981993180",
 "23",
 "10",
 "11098939821764568131087645431296528907277253709936443029379587475821759259406",
 "27918766665310231445021466320959318414450284884582375163563581940319453185",
 "1",
 "20177832565449474772630743317224985532862797657496372535616634430055981993180",
 "1642074362"
]`))
	require.NoError(t, err)

	expValue, err := PrepareCircuitArrayValues([]*big.Int{big.NewInt(10)}, 64)
	require.NoError(t, err)
	valueHash, err := PoseidonHashValue(expValue)
	require.NoError(t, err)
	schema := it.CoreSchemaFromStr(t, "180410020913331409885634153623124536270")
	slotIndex := 2
	operator := 1
	queryHash, err := poseidon.Hash([]*big.Int{
		schema.BigInt(),
		big.NewInt(int64(slotIndex)),
		big.NewInt(int64(operator)),
		big.NewInt(0),
		big.NewInt(1),
		valueHash,
	})
	require.NoError(t, err)

	exp := AtomicQuerySigV2OnChainPubSignals{
		RequestID: big.NewInt(23),
		UserID: it.IDFromStr(
			t, "26109404700696283154998654512117952420503675471097392618762221546565140481"),
		IssuerID:               it.IDFromStr(t, "27918766665310231445021466320959318414450284884582375163563581940319453185"),
		IssuerAuthState:        it.MTHashFromStr(t, "20177832565449474772630743317224985532862797657496372535616634430055981993180"),
		IssuerClaimNonRevState: it.MTHashFromStr(t, "20177832565449474772630743317224985532862797657496372535616634430055981993180"),
		QueryHash:              queryHash,
		Timestamp:              int64(1642074362),
		Merklized:              0,
		IsRevocationChecked:    1,
		Challenge:              big.NewInt(10),
		GlobalRoot:             it.MTHashFromStr(t, "11098939821764568131087645431296528907277253709936443029379587475821759259406"),
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
				ID:    idFromInt("27918766665310231445021466320959318414450284884582375163563581940319453185"),
				State: hashFromInt("20177832565449474772630743317224985532862797657496372535616634430055981993180"),
			},
		},
		Gists: []Gist{
			{
				ID:   idFromInt("26109404700696283154998654512117952420503675471097392618762221546565140481"),
				Root: hashFromInt("11098939821764568131087645431296528907277253709936443029379587475821759259406"),
			},
		},
	}
	j, err := json.Marshal(statesInfo)
	require.NoError(t, err)
	require.Equal(t, wantStatesInfo, statesInfo, string(j))
}

func TestAttrQuerySigV2OnChain_ErrorUserProfileMismatch(t *testing.T) {
	did, err := w3c.ParseDID("did:iden3:polygon:amoy:x81nCirrkbsh7qZrbnzhZtkwfY76wjUmygcoYztcS")
	require.NoError(t, err)
	userID, err := core.IDFromDID(*did)
	require.NoError(t, err)

	inputs := querySigV2OnChainInputs(t)
	inputs.ID = &userID

	err = inputs.Validate()
	require.Equal(t, err.Error(), ErrorUserProfileMismatch)
}
