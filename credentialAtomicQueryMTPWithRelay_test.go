package circuits

import (
	"context"
	"encoding/hex"
	"encoding/json"
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

func TestAtomicQueryMTPWithRelay_PrepareInputs(t *testing.T) {
	userPrivKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	relayPrivKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c40000"
	issuerPrivKHex := "21a5e7321d0e2f3ca1cc6504396e6594a2211544b08c206847cdee96f832421a"
	challenge := new(big.Int).SetInt64(1)
	ctx := context.Background()

	//User
	userIdentity, uClaimsTree, _, _, err, userAuthCoreClaim, userPrivateKey :=
		it.Generate(ctx, userPrivKHex)
	assert.Nil(t, err)

	userState, err := it.CalcStateFromRoots(uClaimsTree)

	userAuthTreeState := TreeState{
		State:          userState, // Note: userState is not going as an Input into the circuit
		ClaimsRoot:     uClaimsTree.Root(),
		RevocationRoot: &merkletree.HashZero,
		RootOfRoots:    &merkletree.HashZero,
	}
	assert.Nil(t, err)

	hIndexAuthEntryUser, _, err := userAuthCoreClaim.HiHv()
	require.NoError(t, err)

	mtpAuthUser, _, err := uClaimsTree.GenerateProof(ctx, hIndexAuthEntryUser,
		uClaimsTree.Root())
	require.NoError(t, err)

	message := big.NewInt(0).SetBytes(challenge.Bytes())

	challengeSignature := userPrivateKey.SignPoseidon(message)

	//Relay
	claimUserStateInRelay, proofUserStateInRelay, relayClaimsTreeRoot, relayRevTreeRoot, relayRootsTreeRoot, relayState, err := generateRelayWithIdenStateClaim(
		relayPrivKHex, userIdentity, userState)
	if err != nil {
		return
	}

	relayTreeState := TreeState{
		State:          relayState,
		ClaimsRoot:     relayClaimsTreeRoot,
		RevocationRoot: relayRevTreeRoot,
		RootOfRoots:    relayRootsTreeRoot,
	}

	// Issuer
	issuerID, iClaimsTree, _, _, err, _, _ := it.Generate(ctx,
		issuerPrivKHex)
	assert.Nil(t, err)

	// issue claim for user
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

	hIndexClaimEntry, hValueClaimEntry, err := issuerCoreClaim.HiHv()
	require.NoError(t, err)

	err = iClaimsTree.Add(ctx, hIndexClaimEntry, hValueClaimEntry)
	assert.Nil(t, err)

	proof, _, err := iClaimsTree.GenerateProof(ctx, hIndexClaimEntry,
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

	authNonRevProof, _ := merkletree.NewProofFromData(true, []*merkletree.Hash{}, nil)

	userNonRevProof := &ClaimNonRevStatus{
		TreeState: userAuthTreeState,
		Proof:     authNonRevProof,
	}

	inputsAuthClaim := Claim{
		//Schema: userAuthClaim.Schema,
		//Slots:            getSlots(userAuthCoreClaim),
		Claim:       userAuthCoreClaim,
		Proof:       mtpAuthUser,
		TreeState:   userAuthTreeState,
		NonRevProof: userNonRevProof,
	}

	inputsUserStateInRelayClaim := Claim{
		//Schema:    userAuthClaim.Schema,
		Claim:     claimUserStateInRelay,
		Proof:     proofUserStateInRelay,
		TreeState: relayTreeState,
	}

	inputsUserClaim := Claim{
		Claim: issuerCoreClaim,
		//Schema: issuerCoreClaim.GetSchemaHash(),
		//Slots:            getSlots(issuerCoreClaim),
		Proof:     proof,
		TreeState: issuerStateAfterClaimAdd,
		IssuerID:  issuerID,
		NonRevProof: &ClaimNonRevStatus{
			TreeState: issuerStateAfterClaimAdd,
			Proof:     proofNotRevoke,
		},
	}

	query := Query{
		SlotIndex: 2,
		Values:    []*big.Int{new(big.Int).SetInt64(10)},
		Operator:  0,
	}

	atomicInputs := AtomicQueryMTPWithRelayInputs{
		ID:        userIdentity,
		AuthClaim: inputsAuthClaim,
		Challenge: challenge,
		Signature: challengeSignature,

		CurrentTimeStamp: time.Unix(1642074362, 0).Unix(),

		UserStateInRelayClaim: inputsUserStateInRelayClaim,

		Claim: inputsUserClaim,

		Query: query,
	}

	inputsJSON, err := atomicInputs.InputsMarshal()
	assert.Nil(t, err)
	expectedJSONInputs := `{"userAuthClaim":["304427537360709784173770334266246861770","0",
"17640206035128972995519606214765283372613874593503528180869261482403155458945",
"20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],
"userAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtpAuxHi":"0","userAuthClaimNonRevMtpAuxHv":"0","userAuthClaimNonRevMtpNoAux":"1","userClaimsTreeRoot":"9763429684850732628215303952870004997159843236039795272605841029866455670219","userRevTreeRoot":"0","userRootsTreeRoot":"0","userID":"379949150130214723420589610911161895495647789006649785264738141299135414272","challenge":"1","challengeSignatureR8x":"8553678144208642175027223770335048072652078621216414881653012537434846327449","challengeSignatureR8y":"5507837342589329113352496188906367161790372084365285966741761856353367255709","challengeSignatureS":"2093461910575977345603199789919760192811763972089699387324401771367839603655","issuerClaim":["3583233690122716044519380227940806650830","379949150130214723420589610911161895495647789006649785264738141299135414272","10","0","30803922965249841627828060161","0","0","0"],"issuerClaimClaimsTreeRoot":"3077200351284676204723270374054827783313480677490603169533924119235084704890","issuerClaimIdenState":"18605292738057394742004097311192572049290380262377486632479765119429313092475","issuerClaimMtp":["0","0","18337129644116656308842422695567930755039142442806278977230099338026575870840","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimRevTreeRoot":"0","issuerClaimRootsTreeRoot":"0","issuerClaimNonRevClaimsTreeRoot":"3077200351284676204723270374054827783313480677490603169533924119235084704890","issuerClaimNonRevRevTreeRoot":"0","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"18605292738057394742004097311192572049290380262377486632479765119429313092475","issuerClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"0","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"1","claimSchema":"180410020913331409885634153623124536270","issuerID":"26599707002460144379092755370384635496563807452878989192352627271768342528","operator":0,"slotIndex":2,"timestamp":"1642074362","value":["10","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"relayProofValidClaimsTreeRoot":"8121168901305742662057879845808052431346752743553205352641990714922661618462","relayProofValidRevTreeRoot":"0","relayProofValidRootsTreeRoot":"0","relayState":"4239448240735161374561925497474400621823161116770305241717998726622296721696","userStateInRelayClaim":["795467278703584189433295357807347445218","379949150130214723420589610911161895495647789006649785264738141299135414272","0","0","0","0","18656147546666944484453899241916469544090258810192803949522794490493271005313","0"],"userStateInRelayClaimMtp":["12411413272899006501067884001808071121528224140660538219214791597550929401851","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]}`

	var actualInputs map[string]interface{}
	err = json.Unmarshal(inputsJSON, &actualInputs)
	assert.Nil(t, err)

	var expectedInputs map[string]interface{}
	err = json.Unmarshal([]byte(expectedJSONInputs), &expectedInputs)
	assert.Nil(t, err)

	assert.Equal(t, expectedInputs, actualInputs)
}

//nolint:unused
func generateRelayWithIdenStateClaim(relayPrivKeyHex string,
	identifier *core.ID, identityState *merkletree.Hash) (*core.Claim,
	*merkletree.Proof, *merkletree.Hash, *merkletree.Hash, *merkletree.Hash,
	*merkletree.Hash, error) {

	ctx := context.Background()
	_, relayClaimsTree, _, _, _, _, _ := it.Generate(ctx, relayPrivKeyHex)

	var schemaHash core.SchemaHash
	schemaEncodedBytes, _ := hex.DecodeString("e22dd9c0f7aef15788c130d4d86c7156")
	copy(schemaHash[:], schemaEncodedBytes)
	valueSlotA, _ := core.NewElemBytesFromInt(identityState.BigInt())
	issuerClaim, err := core.NewClaim(
		schemaHash,
		core.WithIndexID(*identifier),
		core.WithValueData(valueSlotA, core.ElemBytes{}),
	)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	proofIdenStateInRelay, err := addClaimToTree(relayClaimsTree, issuerClaim)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	relayState, err := it.CalcStateFromRoots(relayClaimsTree)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	return issuerClaim, proofIdenStateInRelay, relayClaimsTree.Root(), &merkletree.HashZero, &merkletree.HashZero, relayState, nil
}

//nolint:unused
func addClaimToTree(tree *merkletree.MerkleTree,
	issuerClaim *core.Claim) (*merkletree.Proof, error) {
	index, value, err := issuerClaim.HiHv()
	if err != nil {
		return nil, err
	}

	err = tree.Add(context.Background(), index, value)
	if err != nil {
		return nil, err
	}

	proof, _, err := tree.GenerateProof(context.Background(), index,
		tree.Root())

	return proof, err
}

func TestAtomicQueryMTPWithRelayOutputs_CircuitUnmarshal(t *testing.T) {
	userID, err := idFromIntStr("379949150130214723420589610911161895495647789006649785264738141299135414272")
	assert.NoError(t, err)

	issuerID, err := idFromIntStr("26599707002460144379092755370384635496563807452878989192352627271768342528")
	assert.NoError(t, err)

	relayStateInt, ok := new(big.Int).SetString(
		"4239448240735161374561925497474400621823161116770305241717998726622296721696", 10)
	assert.True(t, ok)
	relayState, err := merkletree.NewHashFromBigInt(relayStateInt)
	assert.NoError(t, err)

	schemaInt, ok := new(big.Int).SetString("180410020913331409885634153623124536270", 10)
	assert.True(t, ok)
	schema := core.NewSchemaHashFromInt(schemaInt)

	values := make([]*big.Int, 64)
	for i := 0; i < 64; i++ {
		values[i] = big.NewInt(0)
	}
	values[0].SetInt64(10)
	values[63].SetInt64(9999)

	expectedOut := AtomicQueryMTPWithRelayPubSignals{
		UserID:      userID,
		RelayState:  relayState,
		Challenge:   big.NewInt(1),
		ClaimSchema: schema,
		SlotIndex:   2,
		Operator:    0,
		Values:      values,
		Timestamp:   int64(1642074362),
		IssuerID:    issuerID,
	}

	out := new(AtomicQueryMTPWithRelayPubSignals)
	err = out.PubSignalsUnmarshal([]byte(
		`["379949150130214723420589610911161895495647789006649785264738141299135414272", "4239448240735161374561925497474400621823161116770305241717998726622296721696", "1", "26599707002460144379092755370384635496563807452878989192352627271768342528", "1642074362", "180410020913331409885634153623124536270", "2", "0", "10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "9999"]`))

	assert.NoError(t, err)
	assert.Equal(t, expectedOut, *out)
}
