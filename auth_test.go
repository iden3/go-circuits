package circuits

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/iden3/go-circuits/identity"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestAuthCircuit_PrepareInputs(t *testing.T) {

	ctx := context.Background()
	privKeyHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	challenge := big.NewInt(1)
	identifier, claim, state, claimsTree, revTree, rootsTree, claimEntryMTP, claimNonRevMTP, signature, err := identity.AuthClaimFullInfo(ctx, privKeyHex, challenge)
	assert.Nil(t, err)

	claimEntryProof := convertMTPtoProof(claimEntryMTP)
	claimNonRevEntryProof := convertMTPtoProof(claimNonRevMTP)

	treeState := TreeState{
		State:          state,
		ClaimsRoot:     claimsTree.Root(),
		RevocationRoot: revTree.Root(),
		RootOfRoots:    rootsTree.Root(),
	}

	c, err := GetCircuit(AuthCircuitID)
	assert.Nil(t, err)

	inputs, err := c.PrepareInputs(AuthInputs{
		ID:    identifier,
		State: treeState,
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
	})
	assert.Nil(t, err)
	fmt.Println(inputs)
	bytesInputs, err := json.Marshal(inputs)
	assert.Nil(t, err)

	expectedJSONInputs := `{"authClaim":["164867201768971999401702181843803888060","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"authClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtpAuxHi":"0","authClaimNonRevMtpAuxHv":"0","authClaimNonRevMtpNoAux":"1","challenge":"1","challengeSignatureR8x":"8553678144208642175027223770335048072652078621216414881653012537434846327449","challengeSignatureR8y":"5507837342589329113352496188906367161790372084365285966741761856353367255709","challengeSignatureS":"2093461910575977345603199789919760192811763972089699387324401771367839603655","claimsTreeRoot":"209113798174833776229979813091844404331713644587766182643501254985715193770","id":"293373448908678327289599234275657468666604586273320428510206058753616052224","revTreeRoot":"0","rootsTreeRoot":"0","state":"15383795261052586569047113011994713909892315748410703061728793744343300034754"}`

	var actualInputs map[string]interface{}
	err = json.Unmarshal(bytesInputs, &actualInputs)
	assert.Nil(t, err)

	var expectedInputs map[string]interface{}
	err = json.Unmarshal([]byte(expectedJSONInputs), &expectedInputs)
	assert.Nil(t, err)

	assert.Equal(t, actualInputs, expectedInputs)
}
