package circuits

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/iden3/go-circuits/identity"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttrQuerySig_PrepareInputs(t *testing.T) {
	userPrivKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	issuerPrivKHex := "21a5e7321d0e2f3ca1cc6504396e6594a2211544b08c206847cdee96f832421a"
	challenge := new(big.Int).SetInt64(1)
	ctx := context.Background()

	userIdentity, uClaimsTree, _, _, err, userAuthCoreClaim, userPrivateKey := identity.Generate(ctx,
		userPrivKHex)
	assert.Nil(t, err)

	state, err := merkletree.HashElems(
		uClaimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(),
		merkletree.HashZero.BigInt())

	userAuthTreeState := TreeState{
		State:          state,
		ClaimsRoot:     uClaimsTree.Root(),
		RevocationRoot: &merkletree.HashZero,
		RootOfRoots:    &merkletree.HashZero,
	}
	assert.Nil(t, err)

	hIndexAuthEntryUser, _, err := claimsIndexValueHashes(*userAuthCoreClaim)
	assert.Nil(t, err)

	mtpProofUser, _, err := uClaimsTree.GenerateProof(ctx,
		hIndexAuthEntryUser, uClaimsTree.Root())
	assert.Nil(t, err)

	message := big.NewInt(0).SetBytes(challenge.Bytes())

	challengeSignature := userPrivateKey.SignPoseidon(message)

	// Issuer
	issuerIdentity, iClaimsTree, _, _, err, issuerAuthClaim, issuerKey := identity.Generate(ctx,
		issuerPrivKHex)
	assert.Nil(t, err)

	// issuer state
	issuerGenesisState, err := merkletree.HashElems(
		iClaimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(),
		merkletree.HashZero.BigInt())
	require.NoError(t, err)

	issuerAuthTreeState := TreeState{
		State:          issuerGenesisState,
		ClaimsRoot:     iClaimsTree.Root(),
		RevocationRoot: &merkletree.HashZero,
		RootOfRoots:    &merkletree.HashZero,
	}

	hIndexAuthEntryIssuer, hValueAuthEntryIssuer, err :=
		claimsIndexValueHashes(*issuerAuthClaim)
	require.NoError(t, err)

	mtpProofIssuer, _, err := iClaimsTree.GenerateProof(ctx,
		hIndexAuthEntryIssuer, iClaimsTree.Root())
	assert.Nil(t, err)

	// issue issuerClaim for user
	dataSlotA, err := core.NewElemBytesFromInt(big.NewInt(10))
	assert.Nil(t, err)

	nonce := 1
	var schemaHash core.SchemaHash

	schemaBytes, err := hex.DecodeString("ce6bb12c96bfd1544c02c289c6b4b987")
	assert.Nil(t, err)

	copy(schemaHash[:], schemaBytes)

	issuerCoreClaim, err := core.NewClaim(
		schemaHash,
		core.WithIndexID(*userIdentity),
		core.WithIndexData(dataSlotA, core.ElemBytes{}),
		core.WithExpirationDate(time.Unix(1669884010,
			0)), //Thu Dec 01 2022 08:40:10 GMT+0000
		core.WithRevocationNonce(uint64(nonce)))
	assert.Nil(t, err)

	hashIndex, hashValue, err := claimsIndexValueHashes(*issuerCoreClaim)
	assert.Nil(t, err)

	commonHash, err := merkletree.HashElems(hashIndex, hashValue)
	require.NoError(t, err)

	claimSignature := issuerKey.SignPoseidon(commonHash.BigInt())

	err = iClaimsTree.Add(ctx, hashIndex, hashValue)
	assert.Nil(t, err)

	proof, _, err := iClaimsTree.GenerateProof(ctx, hashIndex,
		iClaimsTree.Root())
	assert.Nil(t, err)

	stateAfterClaimAdd, err := merkletree.HashElems(
		iClaimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(),
		merkletree.HashZero.BigInt())
	assert.Nil(t, err)

	issuerStateAfterClaimAdd := TreeState{
		State:          stateAfterClaimAdd,
		ClaimsRoot:     iClaimsTree.Root(),
		RevocationRoot: &merkletree.HashZero,
		RootOfRoots:    &merkletree.HashZero,
	}

	issuerRevTreeStorage := memory.NewMemoryStorage()
	issuerRevTree, err := merkletree.NewMerkleTree(ctx, issuerRevTreeStorage,
		40)
	assert.Nil(t, err)

	proofNotRevoke, _, err := issuerRevTree.GenerateProof(ctx,
		big.NewInt(int64(nonce)), issuerRevTree.Root())
	assert.Nil(t, err)

	var authClaim Claim

	inputsAuthClaim := Claim{
		Schema:           authClaim.Schema,
		Claim:            userAuthCoreClaim,
		AProof:           mtpProofUser,
		TreeState:        userAuthTreeState,
		CurrentTimeStamp: time.Unix(1642074362, 0).Unix(),
		NonRevProof: ClaimNonRevStatus{
			TreeState: userAuthTreeState,
			Proof:     mtpProofUser,
		},
	}

	inputsUserClaim := Claim{
		Schema:           issuerCoreClaim.GetSchemaHash(),
		Claim:            issuerCoreClaim,
		AProof:           proof,
		TreeState:        issuerStateAfterClaimAdd,
		CurrentTimeStamp: time.Unix(1642074362, 0).Unix(),
		NonRevProof: ClaimNonRevStatus{
			TreeState: issuerStateAfterClaimAdd,
			Proof:     proofNotRevoke,
		},
		IssuerID: issuerIdentity,
	}

	query := Query{
		SlotIndex: 2,
		Values:    []*big.Int{new(big.Int).SetInt64(10)},
		Operator:  0,
	}

	claimIssuerSignature := BJJSignatureProof{
		BaseSignatureProof: BaseSignatureProof{
			IssuerID:           issuerIdentity,
			IssuerTreeState:    issuerAuthTreeState,
			AuthClaimIssuerMTP: mtpProofIssuer,
		},
		IssuerPublicKey: issuerKey.Public(),
		Signature:       claimSignature,
		HIndex:          merkletree.NewHashFromBigInt(hIndexAuthEntryIssuer),
		HValue:          merkletree.NewHashFromBigInt(hValueAuthEntryIssuer),
	}

	atomicInputs := AtomicQuerySigInputs{
		ID:        userIdentity,
		AuthClaim: inputsAuthClaim,
		Challenge: challenge,
		Signature: challengeSignature,

		CurrentStateTree: userAuthTreeState,

		SignatureProof: claimIssuerSignature,

		Claim: inputsUserClaim,

		Query: query,
	}

	bytesInputs, err := atomicInputs.CircuitMarshal()
	assert.Nil(t, err)

	expectedJSONInputs := `{"userAuthClaim":["269270088098491255471307608775043319525","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"userAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtpAuxHi":"0","userAuthClaimNonRevMtpAuxHv":"0","userAuthClaimNonRevMtpNoAux":"1","challenge":"1","challengeSignatureR8x":"8553678144208642175027223770335048072652078621216414881653012537434846327449","challengeSignatureR8y":"5507837342589329113352496188906367161790372084365285966741761856353367255709","challengeSignatureS":"2093461910575977345603199789919760192811763972089699387324401771367839603655","issuerClaim":["3677203805624134172815825715044445108615","286312392162647260160287083374160163061246635086990474403590223113720496128","10","0","30803922965249841627828060161","0","0","0"],"issuerClaimNonRevClaimsTreeRoot":"12781049434766209895790529815771921100011665835724745028505992240548230711728","issuerClaimNonRevRevTreeRoot":"0","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"20606705619830543359176597576564222044873771515109680973150322899613614552596","issuerClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"0","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"1","claimSchema":"274380136414749538182079640726762994055","issuerClaimSignatureR8x":"16350455878339005535160033892392467617587431512406554457136266319459521562346","issuerClaimSignatureR8y":"14894179842687436294687354107750448313329679878610038101306733562999503453587","issuerClaimSignatureS":"2681759448312288075633080358169130347427026242230450134480518935399355221937","userClaimsTreeRoot":"8033159210005724351649063848617878571712113104821846241291681963936214187701","userState":"5816868615164565912277677884704888703982258184820398645933682814085602171910","userRevTreeRoot":"0","userRootsTreeRoot":"0","userID":"286312392162647260160287083374160163061246635086990474403590223113720496128","issuerAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthHi":"5531954820082616767778003351409281205451440073132087895727199111769673732654","issuerAuthHv":"14324808554535590121751093260129075040263902072955826744017618397253462388668","issuerClaimsTreeRoot":"3007906543589053223183609977424583669571967498470079791401931468580200755448","issuerID":"296941560404583387587196218166209608454370683337298127000644446413747191808","issuerState":"13850938450891658391727543833954835315278162931905851620922327407976321180678","issuerPubKeyX":"9582165609074695838007712438814613121302719752874385708394134542816240804696","issuerPubKeyY":"18271435592817415588213874506882839610978320325722319742324814767882756910515","issuerRevTreeRoot":"0","issuerRootsTreeRoot":"0","operator":0,"slotIndex":2,"timestamp":"1642074362","value":["10","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]}
 `
	var actualInputs map[string]interface{}
	err = json.Unmarshal(bytesInputs, &actualInputs)
	assert.Nil(t, err)

	var expectedInputs map[string]interface{}
	err = json.Unmarshal([]byte(expectedJSONInputs), &expectedInputs)
	assert.Nil(t, err)

	assert.Equal(t, expectedInputs, actualInputs)

}

func TestAtomicQuerySigOutputs_CircuitUnmarshal(t *testing.T) {
	userPrivKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	issuerPrivKHex := "21a5e7321d0e2f3ca1cc6504396e6594a2211544b08c206847cdee96f832421a"
	challenge := new(big.Int).SetInt64(1)
	ctx := context.Background()

	userID, uClaimsTree, _, _, err, _, _ := identity.Generate(ctx,
		userPrivKHex)
	assert.Nil(t, err)

	userState, err := merkletree.HashElems(
		uClaimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(),
		merkletree.HashZero.BigInt())

	// Issuer
	issuerID, iClaimsTree, _, _, err, _, _ := identity.Generate(ctx,
		issuerPrivKHex)
	assert.Nil(t, err)

	issuerState, err := merkletree.HashElems(
		iClaimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(),
		merkletree.HashZero.BigInt())

	claimSchema := "ce6bb12c96bfd1544c02c289c6b4b987" // TODO(illia-korotia): here not big.Int. Is ok?
	slotIndex := "1"
	values := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14"}
	operator := "1"
	timeStamp := strconv.FormatInt(time.Now().Unix(), 10)

	outputsData := []string{userID.BigInt().String(), userState.BigInt().String(), challenge.String(), claimSchema,
		issuerID.BigInt().String(), issuerState.BigInt().String(), slotIndex}
	outputsData = append(outputsData, values...)
	outputsData = append(outputsData, operator, timeStamp)

	data, err := json.Marshal(outputsData)
	assert.NoError(t, err)

	out := new(AtomicQuerySigOutputs)
	err = out.CircuitUnmarshal(data)
	assert.NoError(t, err)

	assert.Equal(t, userID, out.UserID)
	assert.Equal(t, userState, out.UserState)
	assert.Equal(t, challenge, out.Challenge)

	hex, err := out.ClaimSchema.MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, []byte(claimSchema), hex)

	assert.Equal(t, issuerID, out.IssuerID)
	assert.Equal(t, issuerState, out.IssuerState)
	assert.Equal(t, slotIndex, strconv.Itoa(out.SlotIndex))
	assert.Equal(t, len(values), len(out.Values))
	for i, v := range out.Values {
		assert.Equal(t, values[i], v.String())
	}
	assert.Equal(t, operator, strconv.Itoa(out.Operator))
	assert.Equal(t, timeStamp, strconv.FormatInt(out.TimeStamp, 10))
}
