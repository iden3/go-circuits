package circuits

import (
	"encoding/json"
	"flag"
	"math/big"
	"os"
	"testing"

	it "github.com/iden3/go-circuits/v2/testing"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/stretchr/testify/require"
)

var (
	generate = flag.Bool("generate", false, "generate the test files")
)

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

const (
	userPK    = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	issuerPK  = "21a5e7321d0e2f3ca1cc6504396e6594a2211544b08c206847cdee96f832421a"
	timestamp = 1642074362
)

func querySigV2Inputs(t testing.TB) AtomicQuerySigV2Inputs {
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

	return AtomicQuerySigV2Inputs{
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
		CurrentTimeStamp: timestamp,
	}
}

func TestAttrQuerySigV2_PrepareInputs(t *testing.T) {
	in := querySigV2Inputs(t)
	bytesInputs, err := in.InputsMarshal()
	require.Nil(t, err)

	exp := it.TestData(t, "sigV2_inputs", string(bytesInputs), *generate)
	require.JSONEq(t, exp, string(bytesInputs))

}

func TestAttrQuerySigV2_GetPublicStatesInfo(t *testing.T) {
	in := querySigV2Inputs(t)
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
  "gists": []
}`
	require.JSONEq(t, wantStatesInfo, string(bs))
}

func TestAtomicQuerySigOutputs_CircuitUnmarshal(t *testing.T) {
	out := new(AtomicQuerySigV2PubSignals)
	err := out.PubSignalsUnmarshal([]byte(
		`[
 "0",
 "23148936466334350744548790012294489365207440754509988986684797708370051073",
 "2943483356559152311923412925436024635269538717812859789851139200242297094",
 "23",
 "21933750065545691586450392143787330185992517860945727248803138245838110721",
 "1",
 "2943483356559152311923412925436024635269538717812859789851139200242297094",
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

	exp := AtomicQuerySigV2PubSignals{
		RequestID: big.NewInt(23),
		UserID: it.IDFromStr(
			t, "23148936466334350744548790012294489365207440754509988986684797708370051073"),
		IssuerID:               it.IDFromStr(t, "21933750065545691586450392143787330185992517860945727248803138245838110721"),
		IssuerAuthState:        it.MTHashFromStr(t, "2943483356559152311923412925436024635269538717812859789851139200242297094"),
		IssuerClaimNonRevState: it.MTHashFromStr(t, "2943483356559152311923412925436024635269538717812859789851139200242297094"),
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

func hashFromInt(i *big.Int) *merkletree.Hash {
	h, err := merkletree.NewHashFromBigInt(i)
	if err != nil {
		panic(err)
	}
	return h
}
