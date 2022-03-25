package circuits

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/iden3/go-circuits/identity"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
	"github.com/stretchr/testify/assert"
)

func TestAtomicQueryMTPWithRelay_PrepareInputs(t *testing.T) {
	userPrivKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	relayPrivKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c40000"
	issuerPrivKHex := "21a5e7321d0e2f3ca1cc6504396e6594a2211544b08c206847cdee96f832421a"
	challenge := new(big.Int).SetInt64(1)
	ctx := context.Background()

	//User
	userIdentity, uClaimsTree, _, _, err, userAuthClaim, userPrivateKey := identity.Generate(ctx, userPrivKHex)
	assert.Nil(t, err)

	userState, err := identity.CalcStateFromRoots(uClaimsTree)

	userAuthTreeState := TreeState{
		State:          userState, // Note: userState is not going as an input into the circuit
		ClaimsRoot:     uClaimsTree.Root(),
		RevocationRoot: &merkletree.HashZero,
		RootOfRoots:    &merkletree.HashZero,
	}
	assert.Nil(t, err)

	authEntryUser := userAuthClaim.TreeEntry()
	hIndexAuthEntryUser, err := authEntryUser.HIndex()
	assert.Nil(t, err)

	mtpProofUser, _, err := uClaimsTree.GenerateProof(ctx, hIndexAuthEntryUser.BigInt(), uClaimsTree.Root())
	assert.Nil(t, err)
	var mtpAuthUser Proof
	mtpAuthUser.Siblings = mtpProofUser.AllSiblings()
	mtpAuthUser.NodeAux = nil

	if mtpProofUser.NodeAux != nil {
		mtpAuthUser.NodeAux = &NodeAux{
			HIndex: mtpProofUser.NodeAux.Key,
			HValue: mtpProofUser.NodeAux.Key,
		}
	}

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

	var mtpUserStateInRelay Proof
	mtpUserStateInRelay.Siblings = proofUserStateInRelay.AllSiblings()
	mtpUserStateInRelay.NodeAux = nil

	if proofUserStateInRelay.NodeAux != nil {
		mtpUserStateInRelay.NodeAux = &NodeAux{
			HIndex: proofUserStateInRelay.NodeAux.Key,
			HValue: proofUserStateInRelay.NodeAux.Key,
		}
	}

	// Issuer
	issuerID, iClaimsTree, _, _, err, _, _ := identity.Generate(ctx, issuerPrivKHex)
	assert.Nil(t, err)

	// issue claim for user
	dataSlotA, err := core.NewDataSlotFromInt(big.NewInt(10))
	assert.Nil(t, err)

	nonce := 1
	var schemaHash core.SchemaHash

	schemaBytes, err := hex.DecodeString("ce6bb12c96bfd1544c02c289c6b4b987")
	assert.Nil(t, err)

	copy(schemaHash[:], schemaBytes)

	claim, err := core.NewClaim(
		schemaHash,
		core.WithIndexID(*userIdentity),
		core.WithIndexData(dataSlotA, core.DataSlot{}),
		core.WithExpirationDate(time.Unix(1669884010, 0)), //Thu Dec 01 2022 08:40:10 GMT+0000
		core.WithRevocationNonce(uint64(nonce)))
	assert.Nil(t, err)

	claimEntry := claim.TreeEntry()
	hIndexClaimEntry, err := claimEntry.HIndex()
	assert.Nil(t, err)

	err = iClaimsTree.AddEntry(ctx, &claimEntry)
	assert.Nil(t, err)

	proof, _, err := iClaimsTree.GenerateProof(ctx, hIndexClaimEntry.BigInt(), iClaimsTree.Root())
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
	issuerRevTree, err := merkletree.NewMerkleTree(ctx, issuerRevTreeStorage, 40)
	assert.Nil(t, err)

	proofNotRevoke, _, err := issuerRevTree.GenerateProof(ctx, big.NewInt(int64(nonce)), issuerRevTree.Root())
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

	var authClaim Claim

	inputsAuthClaim := Claim{
		Schema:           authClaim.Schema,
		Slots:            getSlots(userAuthClaim),
		Proof:            mtpAuthUser,
		TreeState:        userAuthTreeState,
		CurrentTimeStamp: time.Unix(1642074362, 0).Unix(),
	}

	inputsUserStateInRelayClaim := Claim{
		Schema:           authClaim.Schema,
		Slots:            getSlots(claimUserStateInRelay),
		Proof:            mtpUserStateInRelay,
		TreeState:        relayTreeState,
		CurrentTimeStamp: time.Unix(1642074362, 0).Unix(),
	}

	inputsUserClaim := Claim{
		Schema:           claim.GetSchemaHash(),
		Slots:            getSlots(claim),
		Proof:            mtpClaimProof,
		TreeState:        issuerStateAfterClaimAdd,
		CurrentTimeStamp: time.Unix(1642074362, 0).Unix(),
		IssuerID:         issuerID,
	}

	revocationStatus := RevocationStatus{
		TreeState: issuerStateAfterClaimAdd,
		Proof:     nonRevProof,
	}

	query := Query{
		SlotIndex: 2,
		Values:    []*big.Int{new(big.Int).SetInt64(10)},
		Operator:  0,
	}

	userAuthClaimNonRevProof := Proof{
		Siblings: nil,
		NodeAux:  nil,
	}
	atomicInputs := AtomicQueryMTPWithRelayInputs{
		ID:        userIdentity,
		AuthClaim: inputsAuthClaim,
		Challenge: challenge,
		Signature: challengeSignature,

		CurrentStateTree: userAuthTreeState,

		UserStateInRelayClaim: inputsUserStateInRelayClaim,

		Claim:            inputsUserClaim,
		RevocationStatus: revocationStatus,

		AuthClaimRevStatus: RevocationStatus{
			TreeState: userAuthTreeState,
			Proof:     userAuthClaimNonRevProof,
		},
		Query: query,
	}

	c, err := GetCircuit(AtomicQueryMTPWithRelayCircuitID)
	assert.Nil(t, err)

	inputs, err := c.PrepareInputs(atomicInputs)
	assert.Nil(t, err)

	bytesInputs, err := json.Marshal(inputs)
	assert.Nil(t, err)

	expectedJSONInputs := `{"authClaim":["269270088098491255471307608775043319525","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"authClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtpAuxHi":"0","authClaimNonRevMtpAuxHv":"0","authClaimNonRevMtpNoAux":"1","challenge":"1","challengeSignatureR8x":"8553678144208642175027223770335048072652078621216414881653012537434846327449","challengeSignatureR8y":"5507837342589329113352496188906367161790372084365285966741761856353367255709","challengeSignatureS":"2093461910575977345603199789919760192811763972089699387324401771367839603655","claim":["3677203805624134172815825715044445108615","286312392162647260160287083374160163061246635086990474403590223113720496128","10","0","30803922965249841627828060161","0","0","0"],"claimIssuanceClaimsTreeRoot":"12781049434766209895790529815771921100011665835724745028505992240548230711728","claimIssuanceIdenState":"20606705619830543359176597576564222044873771515109680973150322899613614552596","claimIssuanceMtp":["0","3007906543589053223183609977424583669571967498470079791401931468580200755448","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"claimIssuanceRevTreeRoot":"0","claimIssuanceRootsTreeRoot":"0","claimNonRevIssuerClaimsTreeRoot":"12781049434766209895790529815771921100011665835724745028505992240548230711728","claimNonRevIssuerRevTreeRoot":"0","claimNonRevIssuerRootsTreeRoot":"0","claimNonRevIssuerState":"20606705619830543359176597576564222044873771515109680973150322899613614552596","claimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"claimNonRevMtpAuxHi":"0","claimNonRevMtpAuxHv":"0","claimNonRevMtpNoAux":"1","claimSchema":"274380136414749538182079640726762994055","issuerID":"296941560404583387587196218166209608454370683337298127000644446413747191808","operator":0,"relayProofValidClaimsTreeRoot":"2854665891046135459434995383199781762190358117579623998115936884038963331048","relayProofValidRevTreeRoot":"0","relayProofValidRootsTreeRoot":"0","relayState":"16294564286985950894527527840426853346844847075954975086655280191624111272054","slotIndex":2,"timestamp":"1642074362","userClaimsTreeRoot":"8033159210005724351649063848617878571712113104821846241291681963936214187701","userID":"286312392162647260160287083374160163061246635086990474403590223113720496128","userRevTreeRoot":"0","userRootsTreeRoot":"0","userStateInRelayClaim":["981208330819247466821056791934709559638","286312392162647260160287083374160163061246635086990474403590223113720496128","0","0","0","0","5816868615164565912277677884704888703982258184820398645933682814085602171910","0"],"userStateInRelayClaimMtp":["0","1501244652861114532352800692615798696848833011443509616387313576023182892460","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"value":["10","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]}
`

	var actualInputs map[string]interface{}
	err = json.Unmarshal(bytesInputs, &actualInputs)
	assert.Nil(t, err)

	var expectedInputs map[string]interface{}
	err = json.Unmarshal([]byte(expectedJSONInputs), &expectedInputs)
	assert.Nil(t, err)

	assert.Equal(t, expectedInputs, actualInputs)
}

func generateRelayWithIdenStateClaim(relayPrivKeyHex string, identifier *core.ID, identityState *merkletree.Hash) (*core.Claim, *merkletree.Proof, *merkletree.Hash, *merkletree.Hash, *merkletree.Hash, *merkletree.Hash, error) {
	ctx := context.Background()
	_, relayClaimsTree, _, _, _, _, _ := identity.Generate(ctx, relayPrivKeyHex)

	var schemaHash core.SchemaHash
	schemaEncodedBytes, _ := hex.DecodeString("e22dd9c0f7aef15788c130d4d86c7156")
	copy(schemaHash[:], schemaEncodedBytes)
	valueSlotA, _ := core.NewDataSlotFromInt(identityState.BigInt())
	claim, err := core.NewClaim(
		schemaHash,
		core.WithIndexID(*identifier),
		core.WithValueData(valueSlotA, core.DataSlot{}),
	)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	proofIdenStateInRelay, err := addClaimToTree(relayClaimsTree, claim)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	relayState, err := identity.CalcStateFromRoots(relayClaimsTree)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	return claim, proofIdenStateInRelay, relayClaimsTree.Root(), &merkletree.HashZero, &merkletree.HashZero, relayState, nil
}

func addClaimToTree(tree *merkletree.MerkleTree, claim *core.Claim) (*merkletree.Proof, error) {
	entry := claim.TreeEntry()
	index, _ := entry.HIndex()

	err := tree.AddEntry(context.TODO(), &entry)
	if err != nil {
		return nil, err
	}

	proof, _, err := tree.GenerateProof(context.TODO(), index.BigInt(), tree.Root())

	return proof, err
}
