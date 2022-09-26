package circuits

import (
	"context"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	it "github.com/iden3/go-circuits/testing"
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

	userIdentity, uClaimsTree, _, _, err, userAuthCoreClaim, userPrivateKey := it.Generate(ctx,
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
	issuerIdentity, iClaimsTree, iRevTree, _, err, issuerAuthClaim, issuerKey := it.Generate(ctx,
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

	hIndexAuthEntryIssuer, _, err :=
		claimsIndexValueHashes(*issuerAuthClaim)
	require.NoError(t, err)

	mtpProofIssuer, _, err := iClaimsTree.GenerateProof(ctx,
		hIndexAuthEntryIssuer, iClaimsTree.Root())
	assert.Nil(t, err)

	issuerAuthClaimRevNonce := new(big.Int).SetUint64(issuerAuthClaim.GetRevocationNonce())
	issuerAuthNonRevProof, _, err := iRevTree.GenerateProof(ctx,
		issuerAuthClaimRevNonce, iRevTree.Root())
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

	inputsAuthClaim := Claim{
		//Schema:    authClaim.Schema,
		Claim:     userAuthCoreClaim,
		Proof:     mtpProofUser,
		TreeState: userAuthTreeState,
		NonRevProof: &ClaimNonRevStatus{
			TreeState: userAuthTreeState,
			Proof:     mtpProofUser,
		},
	}

	claimIssuerSignature := BJJSignatureProof{
		IssuerID:           issuerIdentity,
		IssuerTreeState:    issuerAuthTreeState,
		IssuerAuthClaimMTP: mtpProofIssuer,
		Signature:          claimSignature,
		IssuerAuthClaim:    issuerAuthClaim,
		IssuerAuthNonRevProof: ClaimNonRevStatus{
			TreeState: issuerAuthTreeState,
			Proof:     issuerAuthNonRevProof,
		},
	}

	inputsUserClaim := Claim{
		Claim:     issuerCoreClaim,
		Proof:     proof,
		TreeState: issuerStateAfterClaimAdd,
		NonRevProof: &ClaimNonRevStatus{
			TreeState: issuerStateAfterClaimAdd,
			Proof:     proofNotRevoke,
		},
		IssuerID:       issuerIdentity,
		SignatureProof: claimIssuerSignature,
	}

	query := Query{
		SlotIndex: 2,
		Values:    []*big.Int{new(big.Int).SetInt64(10)},
		Operator:  EQ,
	}

	atomicInputs := AtomicQuerySigInputs{
		ID:        userIdentity,
		AuthClaim: inputsAuthClaim,
		Challenge: challenge,
		Signature: challengeSignature,

		CurrentTimeStamp: time.Unix(1642074362, 0).Unix(),

		Claim: inputsUserClaim,

		Query: query,
	}

	bytesInputs, err := atomicInputs.InputsMarshal()
	assert.Nil(t, err)

	expectedJSONInputs := `{"userAuthClaim":["304427537360709784173770334266246861770","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"userAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtpAuxHi":"0","userAuthClaimNonRevMtpAuxHv":"0","userAuthClaimNonRevMtpNoAux":"1","userClaimsTreeRoot":"9763429684850732628215303952870004997159843236039795272605841029866455670219","userState":"18656147546666944484453899241916469544090258810192803949522794490493271005313","userRevTreeRoot":"0","userRootsTreeRoot":"0","userID":"326950639933209984096878120644736617046275723209353386907645117784580620769","challenge":"1","challengeSignatureR8x":"8553678144208642175027223770335048072652078621216414881653012537434846327449","challengeSignatureR8y":"5507837342589329113352496188906367161790372084365285966741761856353367255709","challengeSignatureS":"2093461910575977345603199789919760192811763972089699387324401771367839603655","issuerClaim":["3583233690122716044519380227940806650830","326950639933209984096878120644736617046275723209353386907645117784580620769","10","0","30803922965249841627828060161","0","0","0"],"issuerClaimNonRevClaimsTreeRoot":"3207021420489408759781704265998859845356520135997166469849017145723154981142","issuerClaimNonRevRevTreeRoot":"0","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"8417710727099778489535801646128688637751016436542973560292633751614930843971","issuerClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"0","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"1","claimSchema":"180410020913331409885634153623124536270","issuerID":"425907143642375002864917990538284220073575168146768873727835628763900412385","operator":1,"slotIndex":2,"timestamp":"1642074362","value":["10","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimSignatureR8x":"6842227763866610412659953116601615629320904221263388773153090652557163832443","issuerClaimSignatureR8y":"19295186749740939019845860736157819416161716636875447139986834405590680170925","issuerClaimSignatureS":"406282016772573297987610506034836222864663687934661640790798856248289215819","issuerAuthClaim":["304427537360709784173770334266246861770","0","9582165609074695838007712438814613121302719752874385708394134542816240804696","18271435592817415588213874506882839610978320325722319742324814767882756910515","11203087622270641253","0","0","0"],"issuerAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtpAuxHi":"0","issuerAuthClaimNonRevMtpAuxHv":"0","issuerAuthClaimNonRevMtpNoAux":"1","issuerAuthClaimsTreeRoot":"18337129644116656308842422695567930755039142442806278977230099338026575870840","issuerAuthRevTreeRoot":"0","issuerAuthRootsTreeRoot":"0"}`
	assert.JSONEq(t, expectedJSONInputs, string(bytesInputs))

}

func TestAtomicQuerySigOutputs_CircuitUnmarshal(t *testing.T) {
	userID, err := idFromIntStr("222712906379570502079611869905711649383946316867077911802139171411787317248")
	assert.NoError(t, err)

	userStateInt, ok := new(big.Int).SetString(
		"7608718875990494885422326673876913565155307854054144181362485232187902102852", 10)
	assert.True(t, ok)
	userState, err := merkletree.NewHashFromBigInt(userStateInt)
	assert.NoError(t, err)

	schemaInt, ok := new(big.Int).SetString("210459579859058135404770043788028292398", 10)
	assert.True(t, ok)
	schema := core.NewSchemaHashFromInt(schemaInt)

	issuerClaimNonRevStateInt, ok := new(big.Int).SetString("19221836623970007220538457599669851375427558847917606787084815224761802529201", 10)
	assert.True(t, ok)
	issuerClaimNonRevState, err := merkletree.NewHashFromBigInt(issuerClaimNonRevStateInt)
	assert.Nil(t, err)

	issuerAuthStateInt, ok := new(big.Int).SetString("11672667429383627660992648216772306271234451162443612055001584519010749218959", 10)
	assert.True(t, ok)
	issuerAuthState, err := merkletree.NewHashFromBigInt(issuerAuthStateInt)
	assert.Nil(t, err)

	issuerID, err := idFromIntStr("330477016068568275516898063887311212065482015025379036159122139014924926976")
	assert.Nil(t, err)

	values := make([]*big.Int, 64)
	for i := 0; i < 64; i++ {
		values[i] = big.NewInt(0)
	}
	values[0].SetInt64(20000101)
	values[63].SetInt64(9999)

	timestamp := int64(1651850376)

	expectedOut := AtomicQuerySigPubSignals{
		UserID:                 userID,
		UserState:              userState,
		Challenge:              big.NewInt(84239),
		ClaimSchema:            schema,
		IssuerID:               issuerID,
		IssuerAuthState:        issuerAuthState,
		IssuerClaimNonRevState: issuerClaimNonRevState,
		SlotIndex:              2,
		Values:                 values,
		Operator:               EQ,
		Timestamp:              timestamp,
	}

	out := new(AtomicQuerySigPubSignals)
	err = out.PubSignalsUnmarshal([]byte(
		`["11672667429383627660992648216772306271234451162443612055001584519010749218959", "222712906379570502079611869905711649383946316867077911802139171411787317248", "7608718875990494885422326673876913565155307854054144181362485232187902102852", "84239", "330477016068568275516898063887311212065482015025379036159122139014924926976", "19221836623970007220538457599669851375427558847917606787084815224761802529201", "1651850376", "210459579859058135404770043788028292398", "2", "1", "20000101", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "9999"]`))
	assert.NoError(t, err)

	assert.Equal(t, expectedOut, *out)
}

func hashFromInt(i *big.Int) *merkletree.Hash {
	h, err := merkletree.NewHashFromBigInt(i)
	if err != nil {
		panic(err)
	}
	return h
}
