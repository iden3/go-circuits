package circuits

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/iden3/go-iden3-crypto/poseidon"
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

func TestAttrQuerySigOnChainSmt_PrepareInputs(t *testing.T) {
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

	fmt.Println(state.BigInt().String())
	fmt.Println(uClaimsTree.Root().String())

	// On-chain SMT state proof
	onChainSmt, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)
	assert.Nil(t, err)

	// Note: The identity is considered to have a genesis state, so we don't add it to the tree
	//err = onChainSmt.Add(ctx, userIdentity.BigInt(), state.BigInt())
	//assert.Nil(t, err)

	//this is just to emulate that some other leaves exist in the tree
	err = onChainSmt.Add(ctx, big.NewInt(2), big.NewInt(100))
	assert.Nil(t, err)
	err = onChainSmt.Add(ctx, big.NewInt(4), big.NewInt(300))
	assert.Nil(t, err)
	proofIdentityInSmt, _, err := onChainSmt.GenerateProof(ctx, userIdentity.BigInt(), nil)
	assert.Nil(t, err)

	stateInOnChainSmt := StateInOnChainSmt{
		OnChainSmtRoot: onChainSmt.Root(),
		Proof:          proofIdentityInSmt,
	}

	correlationID := big.NewInt(123456789)
	nullifier, err := poseidon.Hash([]*big.Int{correlationID, userPrivateKey.Public().X, userPrivateKey.Public().Y})
	assert.Nil(t, err)

	nullifierInputs := NullifierInputs{
		CorrelationID: correlationID,
		Nullifier:     nullifier,
	}

	// userID ownership
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

	atomicInputs := AtomicQuerySigOnChainSmtInputs{
		StateInOnChainSmt: stateInOnChainSmt,
		NullifierInputs:   nullifierInputs,

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

	t.Log(string(bytesInputs))
	expectedJSONInputs := `{"correlationID":"123456789","nullifier":"3886931623570934357017887171328389254245198238824798786420210009480671968146","userStateInOnChainSmtMtp":["0","2740674427662457332835454792145677734479634481325332115749498841888350110548","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userStateInOnChainSmtMtpAuxHi":"4","userStateInOnChainSmtMtpAuxHv":"300","userStateInOnChainSmtMtpNoAux":"0","userStateInOnChainSmtRoot":"2960269998131412406135915396987536312795307713692807443361231572350088373156","userAuthClaim":["304427537360709784173770334266246861770","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"userAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtpAuxHi":"0","userAuthClaimNonRevMtpAuxHv":"0","userAuthClaimNonRevMtpNoAux":"1","userClaimsTreeRoot":"9763429684850732628215303952870004997159843236039795272605841029866455670219","userState":"18656147546666944484453899241916469544090258810192803949522794490493271005313","userRevTreeRoot":"0","userRootsTreeRoot":"0","userID":"379949150130214723420589610911161895495647789006649785264738141299135414272","challenge":"1","challengeSignatureR8x":"8553678144208642175027223770335048072652078621216414881653012537434846327449","challengeSignatureR8y":"5507837342589329113352496188906367161790372084365285966741761856353367255709","challengeSignatureS":"2093461910575977345603199789919760192811763972089699387324401771367839603655","issuerClaim":["3583233690122716044519380227940806650830","379949150130214723420589610911161895495647789006649785264738141299135414272","10","0","30803922965249841627828060161","0","0","0"],"issuerClaimNonRevClaimsTreeRoot":"3077200351284676204723270374054827783313480677490603169533924119235084704890","issuerClaimNonRevRevTreeRoot":"0","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"18605292738057394742004097311192572049290380262377486632479765119429313092475","issuerClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"0","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"1","claimSchema":"180410020913331409885634153623124536270","issuerID":"26599707002460144379092755370384635496563807452878989192352627271768342528","operator":1,"slotIndex":2,"timestamp":"1642074362","value":["10","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimSignatureR8x":"18625305647089498634672127449050652473073470525382360069529718632627474482386","issuerClaimSignatureR8y":"14539700345423181413201048131770723125531044953576671601029329833956725811279","issuerClaimSignatureS":"772934080142423067561028786350670095248312416624185973552603152377549415467","issuerAuthClaim":["304427537360709784173770334266246861770","0","9582165609074695838007712438814613121302719752874385708394134542816240804696","18271435592817415588213874506882839610978320325722319742324814767882756910515","11203087622270641253","0","0","0"],"issuerAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtpAuxHi":"0","issuerAuthClaimNonRevMtpAuxHv":"0","issuerAuthClaimNonRevMtpNoAux":"1","issuerAuthClaimsTreeRoot":"18337129644116656308842422695567930755039142442806278977230099338026575870840","issuerAuthRevTreeRoot":"0","issuerAuthRootsTreeRoot":"0"}`

	assert.JSONEq(t, expectedJSONInputs, string(bytesInputs))

}

func TestAtomicQuerySigOnChainSmtOutputs_CircuitUnmarshal(t *testing.T) {
	correlationID, _ := new(big.Int).SetString("123456789", 10)
	nullifier, _ := new(big.Int).SetString("987654321", 10)

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

	expectedOut := AtomicQuerySigOnChainSmtPubSignals{
		CorrelationID:          correlationID,
		Nullifier:              nullifier,
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

	out := new(AtomicQuerySigOnChainSmtPubSignals)
	err = out.PubSignalsUnmarshal([]byte(
		`["11672667429383627660992648216772306271234451162443612055001584519010749218959", "123456789", "987654321", "84239", "330477016068568275516898063887311212065482015025379036159122139014924926976", "19221836623970007220538457599669851375427558847917606787084815224761802529201", "1651850376", "210459579859058135404770043788028292398", "2", "1", "20000101", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "9999"]`))
	assert.NoError(t, err)

	assert.Equal(t, expectedOut, *out)
}
