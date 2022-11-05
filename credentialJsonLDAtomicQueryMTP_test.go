package circuits

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	it "github.com/iden3/go-circuits/testing"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/merklize"
	"github.com/stretchr/testify/require"
)

const testClaimDocument = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/citizenship/v1",
    "https://w3id.org/security/bbs/v1"
  ],
  "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
  "type": ["VerifiableCredential", "PermanentResidentCard"],
  "issuer": "did:example:489398593",
  "identifier": 83627465,
  "name": "Permanent Resident Card",
  "description": "Government of Example Permanent Resident Card.",
  "issuanceDate": "2019-12-03T12:19:52Z",
  "expirationDate": "2029-12-03T12:19:52Z",
  "credentialSubject": {
    "id": "did:example:b34ca6cd37bbf23",
    "type": ["PermanentResident", "Person"],
    "givenName": "JOHN",
    "familyName": "SMITH",
    "gender": "Male",
    "image": "data:image/png;base64,iVBORw0KGgokJggg==",
    "residentSince": "2015-01-01",
    "lprCategory": "C09",
    "lprNumber": "999-999-999",
    "commuterClassification": "C1",
    "birthCountry": "Bahamas",
    "birthDate": "1958-07-17"
  }
}`

func TestJsonLDAtomicQuery_PrepareInputs(t *testing.T) {
	userPrivKHex :=
		"28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	issuerPrivKHex :=
		"21a5e7321d0e2f3ca1cc6504396e6594a2211544b08c206847cdee96f832421a"
	challenge := new(big.Int).SetInt64(1)
	ctx := context.Background()

	userIdentity, uClaimsTree, uRevsTree, _, err, userAuthCoreClaim,
		userPrivateKey := it.Generate(ctx, userPrivKHex)
	require.NoError(t, err)

	state, err := merkletree.HashElems(
		uClaimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(),
		merkletree.HashZero.BigInt())
	require.NoError(t, err)

	userAuthTreeState := TreeState{
		State:          state,
		ClaimsRoot:     uClaimsTree.Root(),
		RevocationRoot: &merkletree.HashZero,
		RootOfRoots:    &merkletree.HashZero,
	}

	hIndexAuthEntryUser, _, err := claimsIndexValueHashes(*userAuthCoreClaim)
	require.NoError(t, err)

	mtpProofUser, _, err := uClaimsTree.GenerateProof(ctx,
		hIndexAuthEntryUser, uClaimsTree.Root())
	require.NoError(t, err)

	message := big.NewInt(0).SetBytes(challenge.Bytes())

	challengeSignature := userPrivateKey.SignPoseidon(message)

	// Issuer
	issuerID, iClaimsTree, issuerRevTree, issuerRoRTree, err, _, _ :=
		it.Generate(ctx, issuerPrivKHex)
	require.NoError(t, err)

	mz, err := merklize.MerklizeJSONLD(ctx, strings.NewReader(testClaimDocument))
	require.NoError(t, err)

	// issue issuerClaim for user
	dataSlotA, err := core.NewElemBytesFromInt(mz.Root().BigInt())
	require.NoError(t, err)

	const (
		nonce       = 1
		otherNonce1 = 2
		otherNonce2 = 3
	)

	var schemaHash core.SchemaHash
	schemaBytes, err := hex.DecodeString("ce6bb12c96bfd1544c02c289c6b4b987")
	require.NoError(t, err)
	copy(schemaHash[:], schemaBytes)

	issuerCoreClaim, err := core.NewClaim(
		schemaHash,
		core.WithIndexID(*userIdentity),
		core.WithIndexData(dataSlotA, core.ElemBytes{}),
		core.WithExpirationDate(time.Unix(1669884010,
			0)), //Thu Dec 01 2022 08:40:10 GMT+0000
		core.WithRevocationNonce(nonce))
	require.NoError(t, err)

	hIndexClaimEntry, hValueClaimEntry, err := claimsIndexValueHashes(*issuerCoreClaim)
	require.NoError(t, err)

	err = iClaimsTree.Add(ctx, hIndexClaimEntry, hValueClaimEntry)
	require.NoError(t, err)

	proof, _, err := iClaimsTree.GenerateProof(ctx, hIndexClaimEntry,
		iClaimsTree.Root())
	require.NoError(t, err)

	// add something to revocation tree so tree is not zeros
	for _, i := range []int64{otherNonce1, otherNonce2} {
		err = issuerRevTree.Add(ctx, big.NewInt(i), big.NewInt(0))
		require.NoError(t, err)
	}

	stateAfterClaimAdd, err := merkletree.HashElems(
		iClaimsTree.Root().BigInt(),
		issuerRevTree.Root().BigInt(),
		issuerRoRTree.Root().BigInt())
	require.NoError(t, err)

	issuerStateAfterClaimAdd := TreeState{
		State:          stateAfterClaimAdd,
		ClaimsRoot:     iClaimsTree.Root(),
		RevocationRoot: issuerRevTree.Root(),
		RootOfRoots:    issuerRoRTree.Root(),
	}

	proofNotRevoke, _, err := issuerRevTree.GenerateProof(ctx,
		big.NewInt(nonce), nil)
	require.NoError(t, err)

	authClaimRevNonce := new(big.Int).
		SetUint64(userAuthCoreClaim.GetRevocationNonce())
	proofAuthClaimNotRevoked, _, err :=
		uRevsTree.GenerateProof(ctx, authClaimRevNonce, nil)
	require.NoError(t, err)

	inputsAuthClaim := ClaimWithMTPProof{
		Claim: userAuthCoreClaim,
		IncProof: MTProof{
			Proof:     mtpProofUser,
			TreeState: userAuthTreeState,
		},
		NonRevProof: MTProof{
			TreeState: userAuthTreeState,
			Proof:     proofAuthClaimNotRevoked,
		},
	}

	inputsUserClaim := ClaimWithMTPProof{
		IssuerID: issuerID,
		Claim:    issuerCoreClaim,
		IncProof: MTProof{
			Proof:     proof,
			TreeState: issuerStateAfterClaimAdd,
		},
		NonRevProof: MTProof{
			TreeState: issuerStateAfterClaimAdd,
			Proof:     proofNotRevoke,
		},
	}

	path, err := merklize.NewPath("http://schema.org/identifier")
	require.NoError(t, err)

	jsonLDProof, value, err := mz.Proof(ctx, path)
	require.NoError(t, err)

	jsonLDValue, err := value.MtEntry()
	require.NoError(t, err)

	query := JsonLDQuery{
		Path:     path,
		Value:    jsonLDValue,
		MTP:      jsonLDProof,
		Values:   []*big.Int{jsonLDValue},
		Operator: EQ,
	}

	atomicInputs := JsonLDAtomicQueryMTPInputs{
		ID:               userIdentity,
		AuthClaim:        inputsAuthClaim,
		Challenge:        challenge,
		Signature:        challengeSignature,
		Claim:            inputsUserClaim,
		CurrentTimeStamp: time.Unix(1642074362, 0).Unix(),
		Query:            query,
	}

	bytesInputs, err := atomicInputs.InputsMarshal()
	require.NoError(t, err)

	expectedJSONInputs := `{"userAuthClaim":["304427537360709784173770334266246861770","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"userAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtpAuxHi":"0","userAuthClaimNonRevMtpAuxHv":"0","userAuthClaimNonRevMtpNoAux":"1","userClaimsTreeRoot":"9763429684850732628215303952870004997159843236039795272605841029866455670219","userState":"18656147546666944484453899241916469544090258810192803949522794490493271005313","userRevTreeRoot":"0","userRootsTreeRoot":"0","userID":"20920305170169595198233610955511031459141100274346276665183631177096036352","challenge":"1","challengeSignatureR8x":"8553678144208642175027223770335048072652078621216414881653012537434846327449","challengeSignatureR8y":"5507837342589329113352496188906367161790372084365285966741761856353367255709","challengeSignatureS":"2093461910575977345603199789919760192811763972089699387324401771367839603655","issuerClaim":["3583233690122716044519380227940806650830","20920305170169595198233610955511031459141100274346276665183631177096036352","17568057213828477233507447080689055308823020388972334380526849356111335110900","0","30803922965249841627828060161","0","0","0"],"issuerClaimClaimsTreeRoot":"12043432325186851834711218335182459998010702175035207867812467115440003729689","issuerClaimIdenState":"7442410153287181122610943549348167471303699811467200353996210395269617163235","issuerClaimMtp":["0","0","18337129644116656308842422695567930755039142442806278977230099338026575870840","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimRevTreeRoot":"11955236168039024258206152167718595733300625004351440056586716560060653311750","issuerClaimRootsTreeRoot":"0","issuerClaimNonRevClaimsTreeRoot":"12043432325186851834711218335182459998010702175035207867812467115440003729689","issuerClaimNonRevRevTreeRoot":"11955236168039024258206152167718595733300625004351440056586716560060653311750","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"7442410153287181122610943549348167471303699811467200353996210395269617163235","issuerClaimNonRevMtp":["16893244256367465864542014032080213413654599301942077056250173615273598292583","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"3","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"0","claimSchema":"180410020913331409885634153623124536270","issuerID":"24839761684028550613296892625503994006188774664975540620786183594699522048","claimPathNotExists":0,"claimPathMtp":["11910293038428617741524804146372123460316909087472110224310684293437832969164","16177004431687368818113912782442107150203001063591538107922536599846633952045","2273332527522244458085120870407367354166812099476912338970230154990132783303","13192918401641087849642106777397606986912934444326373440658673644787217670633","7168654565749461589078377009464061974077279404969163913984304601783416740392","14271173073428930573422493938722323454218890711784989528150404024814136007165","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"claimPathMtpNoAux":"0","claimPathMtpAuxHi":"0","claimPathMtpAuxHv":"0","claimPathKey":"14893038329526541210094612673793094547542854832994245253710267888299004292355","claimPathValue":"83627465","operator":1,"timestamp":"1642074362","value":["83627465","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]}`

	require.JSONEq(t, expectedJSONInputs, string(bytesInputs),
		string(bytesInputs))
}

func TestJsonLDAtomicQueryMTPOutputs_CircuitUnmarshal(t *testing.T) {
	userID, err := idFromIntStr("20920305170169595198233610955511031459141100274346276665183631177096036352")
	require.NoError(t, err)

	userStateInt, ok := new(big.Int).SetString(
		"18656147546666944484453899241916469544090258810192803949522794490493271005313", 10)
	require.True(t, ok)
	userState, err := merkletree.NewHashFromBigInt(userStateInt)
	require.NoError(t, err)

	schemaInt, ok := new(big.Int).SetString("180410020913331409885634153623124536270", 10)
	require.True(t, ok)
	schema := core.NewSchemaHashFromInt(schemaInt)

	issuerClaimIdenStateInt, ok := new(big.Int).SetString("16993161227479379075495985698325116578679629820096885930185446225558281870528", 10)
	require.True(t, ok)
	issuerClaimIdenState, err := merkletree.NewHashFromBigInt(issuerClaimIdenStateInt)
	require.NoError(t, err)

	issuerClaimNonRevStateInt, ok := new(big.Int).SetString("16993161227479379075495985698325116578679629820096885930185446225558281870528", 10)
	require.True(t, ok)
	issuerClaimNonRevState, err := merkletree.NewHashFromBigInt(issuerClaimNonRevStateInt)
	require.NoError(t, err)

	issuerID, err := idFromIntStr("24839761684028550613296892625503994006188774664975540620786183594699522048")
	require.NoError(t, err)

	values := make([]*big.Int, 64)
	for i := 0; i < 64; i++ {
		values[i] = big.NewInt(0)
	}
	values[0].SetInt64(83627465)

	claimPathKeyInt, ok := new(big.Int).SetString(
		"14893038329526541210094612673793094547542854832994245253710267888299004292355", 10)
	require.True(t, ok)
	claimPathKey, err := merkletree.NewHashFromBigInt(claimPathKeyInt)
	require.NoError(t, err)

	timestamp := int64(1642074362)

	expectedOut := JsonLDAtomicQueryMTPPubSignals{
		UserID:                 userID,
		UserState:              userState,
		Challenge:              big.NewInt(1),
		ClaimSchema:            schema,
		IssuerClaimIdenState:   issuerClaimIdenState,
		IssuerClaimNonRevState: issuerClaimNonRevState,
		IssuerID:               issuerID,
		ClaimPathKey:           claimPathKey,
		Values:                 values,
		Operator:               EQ,
		Timestamp:              timestamp,
	}

	out := new(JsonLDAtomicQueryMTPPubSignals)
	err = out.PubSignalsUnmarshal([]byte(
		`[
 "20920305170169595198233610955511031459141100274346276665183631177096036352",
 "18656147546666944484453899241916469544090258810192803949522794490493271005313",
 "1",
 "16993161227479379075495985698325116578679629820096885930185446225558281870528",
 "24839761684028550613296892625503994006188774664975540620786183594699522048",
 "16993161227479379075495985698325116578679629820096885930185446225558281870528",
 "1642074362",
 "180410020913331409885634153623124536270",
 "14893038329526541210094612673793094547542854832994245253710267888299004292355",
 "1",
 "83627465",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
 "0",
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

	require.Equal(t, expectedOut, *out)
}
