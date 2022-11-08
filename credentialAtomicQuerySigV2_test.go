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

	claimJSONLDProof, claimJSONLDProofAux := it.PrepareProof(jsonP)

	pathKey, err := path.MtEntry()
	//pathKey, err := path.Key()
	require.NoError(t, err)

	// Sig claim
	claimSig, err := issuer.SignClaimBBJJ(claim)
	require.NoError(t, err)

	issuerClaimNonRevMtp, issuerClaimNonRevAux, err := issuer.ClaimRevMTP(claim)
	require.NoError(t, err)

	issuerAuthClaimMtp, issuerAuthClaimNodeAux, err := issuer.ClaimRevMTP(issuer.AuthClaim)
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

	inputs := atomicQuerySigV2CircuitInputs{
		UserGenesisID:                   user.ID.BigInt().String(),
		Nonce:                           nonce.String(),
		ClaimSubjectProfileNonce:        nonceSubject.String(),
		IssuerID:                        issuer.ID.BigInt().String(),
		IssuerClaim:                     claim,
		IssuerClaimNonRevClaimsTreeRoot: issuer.Clt.Root().BigInt().String(),
		IssuerClaimNonRevRevTreeRoot:    issuer.Ret.Root().BigInt().String(),
		IssuerClaimNonRevRootsTreeRoot:  issuer.Rot.Root().BigInt().String(),
		IssuerClaimNonRevState:          issuer.State().BigInt().String(),
		IssuerClaimNonRevMtp:            issuerClaimNonRevMtp,
		IssuerClaimNonRevMtpAuxHi:       issuerClaimNonRevAux.Key,
		IssuerClaimNonRevMtpAuxHv:       issuerClaimNonRevAux.Value,
		IssuerClaimNonRevMtpNoAux:       issuerClaimNonRevAux.NoAux,
		IssuerClaimSignatureR8X:         claimSig.R8.X.String(),
		IssuerClaimSignatureR8Y:         claimSig.R8.Y.String(),
		IssuerClaimSignatureS:           claimSig.S.String(),
		IssuerAuthClaim:                 issuer.AuthClaim,
		IssuerAuthClaimMtp:              issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtp:        issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtpAuxHi:   issuerAuthClaimNodeAux.Key,
		IssuerAuthClaimNonRevMtpAuxHv:   issuerAuthClaimNodeAux.Value,
		IssuerAuthClaimNonRevMtpNoAux:   issuerAuthClaimNodeAux.NoAux,
		IssuerAuthClaimsTreeRoot:        issuer.Clt.Root().BigInt().String(),
		IssuerAuthRevTreeRoot:           issuer.Ret.Root().BigInt().String(),
		IssuerAuthRootsTreeRoot:         issuer.Rot.Root().BigInt().String(),
		ClaimSchema:                     "180410020913331409885634153623124536270",

		ClaimPathNotExists: 1, // 0 for inclusion, 1 for non-inclusion
		ClaimPathMtp:       claimJSONLDProof,
		ClaimPathMtpNoAux:  claimJSONLDProofAux.NoAux, // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
		ClaimPathMtpAuxHi:  claimJSONLDProofAux.Key,   // 0 for inclusion proof
		ClaimPathMtpAuxHv:  claimJSONLDProofAux.Value, // 0 for inclusion proof
		ClaimPathKey:       pathKey.String(),          // hash of path in merklized json-ld document
		ClaimPathValue:     valueKey.String(),         // value in this path in merklized json-ld document
		// value in this path in merklized json-ld document

		Operator:  EQ,
		SlotIndex: 2,
		Timestamp: timestamp,
		Value:     values,
	}

	expJson, err := json.Marshal(inputs)
	require.NoError(t, err)
	t.Log(string(expJson))

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
	//userID, err := idFromIntStr("19224224881555258540966250468059781351205177043309252290095510834143232000")
	//require.NoError(t, err)
	//
	//userStateInt, ok := new(big.Int).SetString(
	//	"7608718875990494885422326673876913565155307854054144181362485232187902102852", 10)
	//require.True(t, ok)
	//userState, err := merkletree.NewHashFromBigInt(userStateInt)
	//require.NoError(t, err)
	//
	//schemaInt, ok := new(big.Int).SetString("210459579859058135404770043788028292398", 10)
	//require.True(t, ok)
	//schema := core.NewSchemaHashFromInt(schemaInt)
	//
	//issuerClaimNonRevStateInt, ok := new(big.Int).SetString("19221836623970007220538457599669851375427558847917606787084815224761802529201", 10)
	//require.True(t, ok)
	//issuerClaimNonRevState, err := merkletree.NewHashFromBigInt(issuerClaimNonRevStateInt)
	//require.Nil(t, err)
	//
	//issuerAuthStateInt, ok := new(big.Int).SetString("11672667429383627660992648216772306271234451162443612055001584519010749218959", 10)
	//require.True(t, ok)
	//issuerAuthState, err := merkletree.NewHashFromBigInt(issuerAuthStateInt)
	//require.Nil(t, err)
	//
	//issuerID, err := idFromIntStr("24839761684028550613296892625503994006188774664975540620786183594699522048")
	//require.Nil(t, err)
	//
	//values := make([]*big.Int, 64)
	//for i := 0; i < 64; i++ {
	//	values[i] = big.NewInt(0)
	//}
	//values[0].SetInt64(20000101)
	//values[63].SetInt64(9999)
	//
	//timestamp := int64(1651850376)
	//
	//expectedOut := AtomicQuerySigPubSignals{
	//	UserID:                 userID,
	//	UserState:              userState,
	//	Challenge:              big.NewInt(84239),
	//	ClaimSchema:            schema,
	//	IssuerID:               issuerID,
	//	IssuerAuthState:        issuerAuthState,
	//	IssuerClaimNonRevState: issuerClaimNonRevState,
	//	SlotIndex:              2,
	//	Values:                 values,
	//	Operator:               EQ,
	//	Timestamp:              timestamp,
	//}
	//
	//out := new(AtomicQuerySigPubSignals)
	//err = out.PubSignalsUnmarshal([]byte(
	//	`["11672667429383627660992648216772306271234451162443612055001584519010749218959", "19224224881555258540966250468059781351205177043309252290095510834143232000", "7608718875990494885422326673876913565155307854054144181362485232187902102852", "84239", "24839761684028550613296892625503994006188774664975540620786183594699522048", "19221836623970007220538457599669851375427558847917606787084815224761802529201", "1651850376", "210459579859058135404770043788028292398", "2", "1", "20000101", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "9999"]`))
	//require.NoError(t, err)
	//require.Equal(t, expectedOut, *out)
}

func hashFromInt(i *big.Int) *merkletree.Hash {
	h, err := merkletree.NewHashFromBigInt(i)
	if err != nil {
		panic(err)
	}
	return h
}
