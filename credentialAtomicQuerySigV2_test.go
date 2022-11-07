package circuits

import (
	"context"
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
		Query: JsonLDQuery{
			Path:      path,
			Value:     valueKey,
			MTP:       jsonP,
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
 "1",
 "24357338057394103910029868244681596615276666879950910837900400354886746113",
 "941468466445458410186775788257959899059193009206256072692441148778367618811",
 "21443782015371791400876357388364171246290737482854988499085152504070668289",
 "941468466445458410186775788257959899059193009206256072692441148778367618811",
 "1642074362",
 "180410020913331409885634153623124536270",
 "1",
 "4565618812218816904592638866963205946316329857551756884889133933625594842882",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
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
}

func hashFromInt(i *big.Int) *merkletree.Hash {
	h, err := merkletree.NewHashFromBigInt(i)
	if err != nil {
		panic(err)
	}
	return h
}
