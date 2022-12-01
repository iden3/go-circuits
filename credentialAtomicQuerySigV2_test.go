package circuits

import (
	"context"
	"encoding/json"
	"flag"
	"math/big"
	"os"
	"testing"

	it "github.com/iden3/go-circuits/testing"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/merklize"
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

func TestAttrQuerySigV2_PrepareInputs(t *testing.T) {

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

	// Sig claim
	claimSig, err := issuer.SignClaimBBJJ(claim)
	require.NoError(t, err)

	values := []string{valueKey.String(), "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
		"0", "0",
		"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
		"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"}
	//string array to big.Int array
	valuesBigInt := make([]*big.Int, len(values))
	for i, v := range values {
		in, b := new(big.Int).SetString(v, 10)
		require.True(t, b)
		valuesBigInt[i] = in

	}

	issuerClaimNonRevMtpRaw, _, err := issuer.ClaimRevMTPRaw(claim)
	require.NoError(t, err)

	issuerAuthClaimMtpRaw, _, err := issuer.ClaimMTPRaw(issuer.AuthClaim)
	require.NoError(t, err)

	issuerAuthClaimNonRevMtpRaw, _, err := issuer.ClaimRevMTPRaw(issuer.AuthClaim)
	require.NoError(t, err)

	in := AtomicQuerySigV2Inputs{
		ID:                       &user.ID,
		Nonce:                    nonce,
		ClaimSubjectProfileNonce: nonceSubject,
		Claim: ClaimWithSigProof{
			IssuerID: &issuer.ID,
			Claim:    claim,
			NonRevProof: MTProof{
				TreeState: TreeState{
					State:          issuer.State(),
					ClaimsRoot:     issuer.Clt.Root(),
					RevocationRoot: issuer.Ret.Root(),
					RootOfRoots:    issuer.Rot.Root(),
				},
				Proof: issuerClaimNonRevMtpRaw,
			},
			SignatureProof: BJJSignatureProof{
				Signature:       claimSig,
				IssuerAuthClaim: issuer.AuthClaim,
				IssuerAuthIncProof: MTProof{
					TreeState: TreeState{
						State:          issuer.State(),
						ClaimsRoot:     issuer.Clt.Root(),
						RevocationRoot: issuer.Ret.Root(),
						RootOfRoots:    issuer.Rot.Root(),
					},
					Proof: issuerAuthClaimMtpRaw,
				},
				IssuerAuthNonRevProof: MTProof{
					TreeState: TreeState{
						State:          issuer.State(),
						ClaimsRoot:     issuer.Clt.Root(),
						RevocationRoot: issuer.Ret.Root(),
						RootOfRoots:    issuer.Rot.Root(),
					},
					Proof: issuerAuthClaimNonRevMtpRaw,
				},
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

	exp := it.TestData(t, "sigV2_inputs", string(bytesInputs), *generate)
	require.JSONEq(t, exp, string(bytesInputs))

}

func TestAtomicQuerySigOutputs_CircuitUnmarshal(t *testing.T) {
	out := new(AtomicQuerySigV2PubSignals)
	err := out.PubSignalsUnmarshal([]byte(
		`[
 "0",
 "19104853439462320209059061537253618984153217267677512271018416655565783041",
 "12035569423371053239461605003190702990928630784475264346060457607843543656590",
 "23",
 "23528770672049181535970744460798517976688641688582489375761566420828291073",
 "12035569423371053239461605003190702990928630784475264346060457607843543656590",
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
			t, "19104853439462320209059061537253618984153217267677512271018416655565783041"),
		IssuerID:               it.IDFromStr(t, "23528770672049181535970744460798517976688641688582489375761566420828291073"),
		IssuerAuthState:        it.MTHashFromStr(t, "12035569423371053239461605003190702990928630784475264346060457607843543656590"),
		IssuerClaimNonRevState: it.MTHashFromStr(t, "12035569423371053239461605003190702990928630784475264346060457607843543656590"),
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

func hashFromInt(i *big.Int) *merkletree.Hash {
	h, err := merkletree.NewHashFromBigInt(i)
	if err != nil {
		panic(err)
	}
	return h
}
