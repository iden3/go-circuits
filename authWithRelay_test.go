package circuits

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/iden3/go-circuits/identity"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	"time"
)

func TestAuthWithRelayCircuit_PrepareInputs(t *testing.T) {

	ctx := context.Background()
	privKeyHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	challenge := big.NewInt(1)
	identifier, claim, state, claimsTree, revTree, rootsTree, claimMTP, claimNonRevMTP, signature, err := identity.AuthClaimFullInfo(ctx, privKeyHex, challenge)
	assert.Nil(t, err)

	claimEntryProof := convertMTPtoProof(claimMTP)
	claimNonRevEntryProof := convertMTPtoProof(claimNonRevMTP)

	treeState := TreeState{
		State:          state,
		ClaimsRoot:     claimsTree.Root(),
		RevocationRoot: revTree.Root(),
		RootOfRoots:    rootsTree.Root(),
	}

	c, err := GetCircuit(AuthWithRelayCircuitID)
	assert.Nil(t, err)

	//Relay
	relayPrivKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c0000f"
	claimUserStateInRelay, proofUserStateInRelay, relayClaimsTreeRoot, relayRevTreeRoot, relayRootsTreeRoot, relayState, err := generateRelayWithIdenStateClaim(
		relayPrivKHex, identifier, state)
	if err != nil {
		return
	}

	relayTreeState := TreeState{
		State:          relayState,
		ClaimsRoot:     relayClaimsTreeRoot,
		RevocationRoot: relayRevTreeRoot,
		RootOfRoots:    relayRootsTreeRoot,
	}

	mtpUserStateInRelay := convertMTPtoProof(proofUserStateInRelay)

	var authClaim Claim

	inputs, err := c.PrepareInputs(AuthWithRelayInputs{
		ID: identifier,
		//State: treeState,
		AuthClaim: Claim{
			Schema:           claim.GetSchemaHash(),
			Slots:            getSlots(claim),
			Proof:            claimEntryProof,
			TreeState:        treeState,
			CurrentTimeStamp: 0,
		},
		AuthClaimNonRevocationProof: claimNonRevEntryProof,
		Signature:                   signature,
		Challenge:                   challenge.Int64(),

		UserStateInRelayClaim: Claim{
			Schema:           authClaim.Schema,
			Slots:            getSlots(claimUserStateInRelay),
			Proof:            mtpUserStateInRelay,
			TreeState:        relayTreeState,
			CurrentTimeStamp: time.Unix(1642074362, 0).Unix(),
		},
	})
	assert.Nil(t, err)
	fmt.Println(inputs)
	bytesInputs, err := json.Marshal(inputs)
	assert.Nil(t, err)

	expectedJSONInputs := `{"authClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaim":["164867201768971999401702181843803888060","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"authClaimNonRevMtpAuxHi":"0","authClaimNonRevMtpAuxHv":"0","authClaimNonRevMtpNoAux":"1","challenge":"1","challengeSignatureR8x":"8553678144208642175027223770335048072652078621216414881653012537434846327449","challengeSignatureR8y":"5507837342589329113352496188906367161790372084365285966741761856353367255709","challengeSignatureS":"2093461910575977345603199789919760192811763972089699387324401771367839603655","claimsTreeRoot":"209113798174833776229979813091844404331713644587766182643501254985715193770","revTreeRoot":"0","rootsTreeRoot":"0","state":"15383795261052586569047113011994713909892315748410703061728793744343300034754","userID":"293373448908678327289599234275657468666604586273320428510206058753616052224","relayState":"5541214523684768955284243741906054311991756887637950319887407727291942261400","userStateInRelayClaimMtp":["0","0","231888852374920189015718116864834487284991054513332054341343074726040365070","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userStateInRelayClaim":["928251232571379559706167670634346311933","293373448908678327289599234275657468666604586273320428510206058753616052224","0","0","0","0","15383795261052586569047113011994713909892315748410703061728793744343300034754","0"],"relayProofValidClaimsTreeRoot":"12777747777340339231536368858395781335116708052428475721993003641461736630111","relayProofValidRevTreeRoot":"0","relayProofValidRootsTreeRoot":"0"}`

	var actualInputs map[string]interface{}
	err = json.Unmarshal(bytesInputs, &actualInputs)
	assert.Nil(t, err)

	var expectedInputs map[string]interface{}
	err = json.Unmarshal([]byte(expectedJSONInputs), &expectedInputs)
	assert.Nil(t, err)

	assert.Equal(t, expectedInputs, actualInputs)
}
