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

func TestAtomicQueryMTPWithRelay_PrepareInputs(t *testing.T) {
	userPrivKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	relayPrivKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c40000"
	issuerPrivKHex := "21a5e7321d0e2f3ca1cc6504396e6594a2211544b08c206847cdee96f832421a"
	challenge := new(big.Int).SetInt64(1)
	ctx := context.Background()

	//User
	userIdentity, uClaimsTree, _, _, err, userAuthCoreClaim, userPrivateKey :=
		identity.Generate(ctx, userPrivKHex)
	assert.Nil(t, err)

	userState, err := identity.CalcStateFromRoots(uClaimsTree)

	userAuthTreeState := TreeState{
		State:          userState, // Note: userState is not going as an input into the circuit
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
	issuerID, iClaimsTree, _, _, err, _, _ := identity.Generate(ctx,
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

	var mtpClaimProof Proof
	mtpClaimProof.Siblings = proof.AllSiblings()
	mtpClaimProof.NodeAux = nil

	if proof.NodeAux != nil {
		mtpClaimProof.NodeAux = &NodeAux{
			HIndex: proof.NodeAux.Key,
			HValue: proof.NodeAux.Key,
		}
	}

	issuerRevTreeStorage := memory.NewMemoryStorage()
	issuerRevTree, err := merkletree.NewMerkleTree(ctx, issuerRevTreeStorage,
		40)
	assert.Nil(t, err)

	proofNotRevoke, _, err := issuerRevTree.GenerateProof(ctx,
		big.NewInt(int64(nonce)), issuerRevTree.Root())
	assert.Nil(t, err)

	var nonRevProof Proof
	nonRevProof.Siblings = proofNotRevoke.AllSiblings()
	nonRevProof.NodeAux = nil

	if proofNotRevoke.NodeAux != nil {
		nonRevProof.NodeAux = &NodeAux{
			HIndex: proofNotRevoke.NodeAux.Key,
			HValue: proofNotRevoke.NodeAux.Key,
		}
	}

	var userAuthClaim Claim
	authNonRevProof, _ := merkletree.NewProofFromData(true, []*merkletree.Hash{}, nil)

	userNonRevProof := ClaimNonRevStatus{
		TreeState: userAuthTreeState,
		Proof:     authNonRevProof,
	}

	inputsAuthClaim := Claim{
		Schema: userAuthClaim.Schema,
		//Slots:            getSlots(userAuthCoreClaim),
		Claim:            userAuthCoreClaim,
		AProof:           mtpAuthUser,
		TreeState:        userAuthTreeState,
		CurrentTimeStamp: time.Unix(1642074362, 0).Unix(),
		NonRevProof:      userNonRevProof,
	}

	inputsUserStateInRelayClaim := Claim{
		Schema: userAuthClaim.Schema,
		//Slots:            getSlots(claimUserStateInRelay),
		Claim:            claimUserStateInRelay,
		AProof:           proofUserStateInRelay,
		TreeState:        relayTreeState,
		CurrentTimeStamp: time.Unix(1642074362, 0).Unix(),
	}

	inputsUserClaim := Claim{
		Claim:  issuerCoreClaim,
		Schema: issuerCoreClaim.GetSchemaHash(),
		//Slots:            getSlots(issuerCoreClaim),
		AProof:           proof,
		TreeState:        issuerStateAfterClaimAdd,
		CurrentTimeStamp: time.Unix(1642074362, 0).Unix(),
		IssuerID:         issuerID,
		NonRevProof: ClaimNonRevStatus{
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

		//CurrentStateTree: userAuthTreeState,

		UserStateInRelayClaim: inputsUserStateInRelayClaim,

		Claim: inputsUserClaim,

		Query: query,
	}

	inputsJSON, err := atomicInputs.CircuitMarshal()
	assert.Nil(t, err)

	expectedJSONInputs := `{"userAuthClaim":["269270088098491255471307608775043319525","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"userAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtpAuxHi":"0","userAuthClaimNonRevMtpAuxHv":"0","userAuthClaimNonRevMtpNoAux":"1","challenge":"1","challengeSignatureR8x":"8553678144208642175027223770335048072652078621216414881653012537434846327449","challengeSignatureR8y":"5507837342589329113352496188906367161790372084365285966741761856353367255709","challengeSignatureS":"2093461910575977345603199789919760192811763972089699387324401771367839603655","issuerClaim":["3677203805624134172815825715044445108615","286312392162647260160287083374160163061246635086990474403590223113720496128","10","0","30803922965249841627828060161","0","0","0"],"issuerClaimClaimsTreeRoot":"12781049434766209895790529815771921100011665835724745028505992240548230711728","issuerClaimIdenState":"20606705619830543359176597576564222044873771515109680973150322899613614552596","issuerClaimMtp":["0","3007906543589053223183609977424583669571967498470079791401931468580200755448","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimRevTreeRoot":"0","issuerClaimRootsTreeRoot":"0","issuerClaimNonRevClaimsTreeRoot":"12781049434766209895790529815771921100011665835724745028505992240548230711728","issuerClaimNonRevRevTreeRoot":"0","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"20606705619830543359176597576564222044873771515109680973150322899613614552596","issuerClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"0","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"1","claimSchema":"274380136414749538182079640726762994055","issuerID":"296941560404583387587196218166209608454370683337298127000644446413747191808","operator":0,"relayProofValidClaimsTreeRoot":"2854665891046135459434995383199781762190358117579623998115936884038963331048","relayProofValidRevTreeRoot":"0","relayProofValidRootsTreeRoot":"0","relayState":"16294564286985950894527527840426853346844847075954975086655280191624111272054","slotIndex":2,"timestamp":"1642074362","userClaimsTreeRoot":"8033159210005724351649063848617878571712113104821846241291681963936214187701","userID":"286312392162647260160287083374160163061246635086990474403590223113720496128","userRevTreeRoot":"0","userRootsTreeRoot":"0","userStateInRelayClaim":["981208330819247466821056791934709559638","286312392162647260160287083374160163061246635086990474403590223113720496128","0","0","0","0","5816868615164565912277677884704888703982258184820398645933682814085602171910","0"],"userStateInRelayClaimMtp":["0","1501244652861114532352800692615798696848833011443509616387313576023182892460","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"value":["10","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]}
`

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
	_, relayClaimsTree, _, _, _, _, _ := identity.Generate(ctx, relayPrivKeyHex)

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

	relayState, err := identity.CalcStateFromRoots(relayClaimsTree)
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
	userPrivKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	issuerPrivKHex := "21a5e7321d0e2f3ca1cc6504396e6594a2211544b08c206847cdee96f832421a"
	challenge := new(big.Int).SetInt64(1)
	ctx := context.Background()

	userID, uClaimsTree, _, _, err, _, _ := identity.Generate(ctx,
		userPrivKHex)
	assert.Nil(t, err)

	relayState, err := merkletree.HashElems(
		uClaimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(),
		merkletree.HashZero.BigInt())

	// Issuer
	issuerID, _, _, _, err, _, _ := identity.Generate(ctx,
		issuerPrivKHex)
	assert.Nil(t, err)

	claimSchema := "ce6bb12c96bfd1544c02c289c6b4b987" // TODO(illia-korotia): here not big.Int. Is ok?
	slotIndex := "1"
	value := "1"
	operator := "1"
	timeStamp := strconv.FormatInt(time.Now().Unix(), 10)

	outputsData := []string{
		userID.BigInt().String(), relayState.BigInt().String(), challenge.String(), claimSchema, slotIndex,
		operator, value, timeStamp, issuerID.BigInt().String(),
	}

	data, err := json.Marshal(outputsData)
	assert.NoError(t, err)

	out := new(AtomicQueryMTPWithRelayOutputs)
	err = out.CircuitUnmarshal(data)
	assert.NoError(t, err)

	assert.Equal(t, userID, out.UserID)
	assert.Equal(t, relayState, out.RelayState)
	assert.Equal(t, challenge, out.Challenge)

	hexSchema, err := out.ClaimSchema.MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, claimSchema, string(hexSchema))

	assert.Equal(t, slotIndex, strconv.Itoa(out.SlotIndex))
	assert.Equal(t, operator, strconv.Itoa(out.Operator))
	assert.Equal(t, value, out.Value.String())
	assert.Equal(t, timeStamp, strconv.FormatInt(out.TimeStamp, 10))
	assert.Equal(t, issuerID, out.IssuerID)
}
