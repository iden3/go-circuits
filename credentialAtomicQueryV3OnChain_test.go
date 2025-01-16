package circuits

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	it "github.com/iden3/go-circuits/v2/testing"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/require"
)

func createV3OnChaneInputs_Sig(t testing.TB) AtomicQueryV3OnChainInputs {
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

	gTree := it.GISTTree(context.Background())
	err := gTree.Add(context.Background(), issuer.ID.BigInt(), issuer.State(t).BigInt())
	require.NoError(t, err)
	globalProof, _, err := gTree.GenerateProof(context.Background(), user.ID.BigInt(), nil)
	require.NoError(t, err)
	authClaimIncMTP, _ := user.ClaimMTPRaw(t, user.AuthClaim)
	authClaimNonRevMTP, _ := user.ClaimRevMTPRaw(t, user.AuthClaim)
	require.NoError(t, err)
	challenge := big.NewInt(10)
	signature, err := user.SignBBJJ(challenge.Bytes())
	require.NoError(t, err)

	in := AtomicQueryV3OnChainInputs{
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
		CurrentTimeStamp:   timestamp,
		ProofType:          BJJSignatureProofType,
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
		LinkNonce: big.NewInt(0),
		VerifierID: it.IDFromStr(
			t, "21929109382993718606847853573861987353620810345503358891473103689157378049"),
		NullifierSessionID: big.NewInt(32),
		IsBJJAuthEnabled:   1,
	}

	return in
}

func TestAttrQueryV3OnChain_SigPart_PrepareInputs(t *testing.T) {
	in := createV3OnChaneInputs_Sig(t)

	bytesInputs, err := in.InputsMarshal()
	require.Nil(t, err)

	fmt.Println(string(bytesInputs))

	exp := it.TestData(t, "onchain_V3_sig_inputs", string(bytesInputs), *generate)
	require.JSONEq(t, exp, string(bytesInputs))
}

func TestAttrQueryV3OnChain_SigPart_GetPublicStatesInfo(t *testing.T) {
	in := createV3OnChaneInputs_Sig(t)

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

func TestAttrQueryV3OnChain_SigPart_Noop_PrepareInputs(t *testing.T) {

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

	gTree := it.GISTTree(context.Background())
	err := gTree.Add(context.Background(), issuer.ID.BigInt(), issuer.State(t).BigInt())
	require.NoError(t, err)
	globalProof, _, err := gTree.GenerateProof(context.Background(), user.ID.BigInt(), nil)
	require.NoError(t, err)
	authClaimIncMTP, _ := user.ClaimMTPRaw(t, user.AuthClaim)
	authClaimNonRevMTP, _ := user.ClaimRevMTPRaw(t, user.AuthClaim)
	require.NoError(t, err)
	challenge := big.NewInt(10)
	signature, err := user.SignBBJJ(challenge.Bytes())
	require.NoError(t, err)

	in := AtomicQueryV3OnChainInputs{
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
			Operator:   NOOP,
			Values:     nil,
			SlotIndex:  2,
		},
		CurrentTimeStamp:   timestamp,
		ProofType:          BJJSignatureProofType,
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
		LinkNonce: big.NewInt(0),
		VerifierID: it.IDFromStr(
			t, "21929109382993718606847853573861987353620810345503358891473103689157378049"),
		NullifierSessionID: big.NewInt(32),
		IsBJJAuthEnabled:   1,
	}

	bytesInputs, err := in.InputsMarshal()
	require.Nil(t, err)

	exp := it.TestData(t, "onchain_V3_sig_noop_inputs", string(bytesInputs), *generate)
	require.JSONEq(t, exp, string(bytesInputs))
}

func TestAttrQueryV3OnChain_MTPPart_PrepareInputs(t *testing.T) {

	user := it.NewIdentity(t, userPK)
	issuer := it.NewIdentity(t, issuerPK)

	nonce := big.NewInt(0)

	subjectID := user.ID
	nonceSubject := big.NewInt(0)

	claim := it.DefaultUserClaim(t, subjectID)

	issuer.AddClaim(t, claim)

	issuerClaimMtp, _ := issuer.ClaimMTPRaw(t, claim)

	issuerClaimNonRevMtp, _ := issuer.ClaimRevMTPRaw(t, claim)

	gTree := it.GISTTree(context.Background())
	err := gTree.Add(context.Background(), issuer.ID.BigInt(), issuer.State(t).BigInt())
	require.NoError(t, err)
	globalProof, _, err := gTree.GenerateProof(context.Background(), user.ID.BigInt(), nil)
	require.NoError(t, err)
	authClaimIncMTP, _ := user.ClaimMTPRaw(t, user.AuthClaim)
	authClaimNonRevMTP, _ := user.ClaimRevMTPRaw(t, user.AuthClaim)
	require.NoError(t, err)
	challenge := big.NewInt(10)
	signature, err := user.SignBBJJ(challenge.Bytes())
	require.NoError(t, err)

	in := AtomicQueryV3OnChainInputs{
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
		CurrentTimeStamp:   timestamp,
		ProofType:          Iden3SparseMerkleTreeProofType,
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
		LinkNonce: big.NewInt(0),
		VerifierID: it.IDFromStr(
			t, "21929109382993718606847853573861987353620810345503358891473103689157378049"),
		NullifierSessionID: big.NewInt(32),
		IsBJJAuthEnabled:   1,
	}

	bytesInputs, err := in.InputsMarshal()
	require.Nil(t, err)

	exp := it.TestData(t, "onchain_V3_mtp_inputs", string(bytesInputs), *generate)
	t.Log(string(bytesInputs))
	require.JSONEq(t, exp, string(bytesInputs))
}

func TestAtomicQueryV3OnChainOutputs_Sig_CircuitUnmarshal(t *testing.T) {
	out := new(AtomicQueryV3OnChainPubSignals)
	err := out.PubSignalsUnmarshal([]byte(
		`[
		"26109404700696283154998654512117952420503675471097392618762221546565140481",
		"1985992055626993205360700288228074716165415322842329919733176531545165024097",
		"2943483356559152311923412925436024635269538717812859789851139200242297094",
		"0",
		"0",
		"0",
		"0",
		"23",
		"10",
		"20177832565449474772630743317224985532862797657496372535616634430055981993180",
		"27918766665310231445021466320959318414450284884582375163563581940319453185",
		"20177832565449474772630743317224985532862797657496372535616634430055981993180",
		"1642074362",
		"1"
		]`))
	require.NoError(t, err)

	expValue, err := PrepareCircuitArrayValues([]*big.Int{big.NewInt(10)}, 64)
	require.NoError(t, err)
	valueHash, err := PoseidonHashValue(expValue)
	require.NoError(t, err)
	schema := it.CoreSchemaFromStr(t, "180410020913331409885634153623124536270")
	slotIndex := 2
	operator := 1
	firstPartQueryHash, err := poseidon.Hash([]*big.Int{
		schema.BigInt(),
		big.NewInt(int64(slotIndex)),
		big.NewInt(int64(operator)),
		big.NewInt(0),
		big.NewInt(1),
		valueHash,
	})
	require.NoError(t, err)
	queryHash, err := poseidon.Hash([]*big.Int{
		firstPartQueryHash,
		big.NewInt(int64(1)),
		big.NewInt(int64(1)),
		big.NewInt(0),
		big.NewInt(0),
		new(big.Int),
	})
	require.NoError(t, err)

	exp := AtomicQueryV3OnChainPubSignals{
		RequestID: big.NewInt(23),
		UserID: it.IDFromStr(
			t, "26109404700696283154998654512117952420503675471097392618762221546565140481"),
		IssuerID:               it.IDFromStr(t, "27918766665310231445021466320959318414450284884582375163563581940319453185"),
		IssuerState:            it.MTHashFromStr(t, "2943483356559152311923412925436024635269538717812859789851139200242297094"),
		IssuerClaimNonRevState: it.MTHashFromStr(t, "20177832565449474772630743317224985532862797657496372535616634430055981993180"),
		QueryHash:              queryHash,
		Timestamp:              int64(1642074362),
		Challenge:              big.NewInt(10),
		GlobalRoot:             it.MTHashFromStr(t, "20177832565449474772630743317224985532862797657496372535616634430055981993180"),
		ProofType:              0,
		OperatorOutput:         big.NewInt(0),
		LinkID:                 big.NewInt(0),
		Nullifier:              big.NewInt(0),
		IsBJJAuthEnabled:       1,
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
				State: hashFromInt("2943483356559152311923412925436024635269538717812859789851139200242297094"),
			},
			{
				ID:    idFromInt("27918766665310231445021466320959318414450284884582375163563581940319453185"),
				State: hashFromInt("20177832565449474772630743317224985532862797657496372535616634430055981993180"),
			},
		},
		Gists: []Gist{
			{
				ID:   idFromInt("26109404700696283154998654512117952420503675471097392618762221546565140481"),
				Root: hashFromInt("20177832565449474772630743317224985532862797657496372535616634430055981993180"),
			},
		},
	}
	j, err := json.Marshal(statesInfo)
	require.NoError(t, err)
	require.Equal(t, wantStatesInfo, statesInfo, string(j))
}

func TestAtomicQueryV3OnChainOutputs_MTP_CircuitUnmarshal(t *testing.T) {
	out := new(AtomicQueryV3OnChainPubSignals)
	err := out.PubSignalsUnmarshal([]byte(
		`[
		"26109404700696283154998654512117952420503675471097392618762221546565140481",
		"1985992055626993205360700288228074716165415322842329919733176531545165024097",
		"2943483356559152311923412925436024635269538717812859789851139200242297094",
		"0",
		"0",
		"0",
		"1",
		"23",
		"10",
		"20177832565449474772630743317224985532862797657496372535616634430055981993180",
		"27918766665310231445021466320959318414450284884582375163563581940319453185",
		"20177832565449474772630743317224985532862797657496372535616634430055981993180",
		"1642074362",
		"1"
	]`))
	require.NoError(t, err)

	expValue, err := PrepareCircuitArrayValues([]*big.Int{big.NewInt(10)}, 64)
	require.NoError(t, err)
	valueHash, err := PoseidonHashValue(expValue)
	require.NoError(t, err)
	schema := it.CoreSchemaFromStr(t, "180410020913331409885634153623124536270")
	slotIndex := 2
	operator := 1

	firstPartQueryHash, err := poseidon.Hash([]*big.Int{
		schema.BigInt(),
		big.NewInt(int64(slotIndex)),
		big.NewInt(int64(operator)),
		big.NewInt(0),
		big.NewInt(1),
		valueHash,
	})
	require.NoError(t, err)
	queryHash, err := poseidon.Hash([]*big.Int{
		firstPartQueryHash,
		big.NewInt(int64(1)),
		big.NewInt(int64(1)),
		big.NewInt(0),
		big.NewInt(0),
		new(big.Int),
	})

	require.NoError(t, err)

	exp := AtomicQueryV3OnChainPubSignals{
		RequestID: big.NewInt(23),
		UserID: it.IDFromStr(
			t, "26109404700696283154998654512117952420503675471097392618762221546565140481"),
		IssuerID:               it.IDFromStr(t, "27918766665310231445021466320959318414450284884582375163563581940319453185"),
		IssuerClaimNonRevState: it.MTHashFromStr(t, "20177832565449474772630743317224985532862797657496372535616634430055981993180"),
		QueryHash:              queryHash,
		Timestamp:              int64(1642074362),
		Challenge:              big.NewInt(10),
		GlobalRoot:             it.MTHashFromStr(t, "20177832565449474772630743317224985532862797657496372535616634430055981993180"),
		ProofType:              1,
		IssuerState:            it.MTHashFromStr(t, "2943483356559152311923412925436024635269538717812859789851139200242297094"),
		OperatorOutput:         big.NewInt(0),
		LinkID:                 big.NewInt(0),
		Nullifier:              big.NewInt(0),
		IsBJJAuthEnabled:       1,
	}

	jsonOut, err := json.Marshal(out)
	require.NoError(t, err)
	jsonExp, err := json.Marshal(exp)
	require.NoError(t, err)

	require.JSONEq(t, string(jsonExp), string(jsonOut))
}
