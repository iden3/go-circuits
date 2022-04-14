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
		Challenge:                   challenge,
	})
	assert.Nil(t, err)
	fmt.Println(inputs)
	bytesInputs, err := json.Marshal(inputs)
	assert.Nil(t, err)

	expectedJSONInputs := `{"userAuthClaim":["269270088098491255471307608775043319525","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"userAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtpAuxHi":"0","userAuthClaimNonRevMtpAuxHv":"0","userAuthClaimNonRevMtpNoAux":"1","challenge":"1","challengeSignatureR8x":"8553678144208642175027223770335048072652078621216414881653012537434846327449","challengeSignatureR8y":"5507837342589329113352496188906367161790372084365285966741761856353367255709","challengeSignatureS":"2093461910575977345603199789919760192811763972089699387324401771367839603655","userClaimsTreeRoot":"8033159210005724351649063848617878571712113104821846241291681963936214187701","userID":"286312392162647260160287083374160163061246635086990474403590223113720496128","userRevTreeRoot":"0","userRootsTreeRoot":"0","userState":"5816868615164565912277677884704888703982258184820398645933682814085602171910"}
`

	var actualInputs map[string]interface{}
	err = json.Unmarshal(bytesInputs, &actualInputs)
	assert.Nil(t, err)

	var expectedInputs map[string]interface{}
	err = json.Unmarshal([]byte(expectedJSONInputs), &expectedInputs)
	assert.Nil(t, err)

	assert.Equal(t, actualInputs, expectedInputs)
}

func TestAuthCircuit_CircuitUnmarshal (t *testing.T) {
	// generate mock data.
	ctx := context.Background()
	privKeyHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	challenge := big.NewInt(1)
	identifier, _, state, _, _, _, _, _, _, err := identity.AuthClaimFullInfo(ctx, privKeyHex, challenge)
	assert.NoError(t, err)

	out := []string{challenge.String(), state.BigInt().String(), identifier.BigInt().String()}
	bytesOut, err := json.Marshal(out)
	assert.NoError(t, err)

	ao := AuthOutputs{}
	err = ao.CircuitUnmarshal(bytesOut)
	assert.NoError(t, err)
	assert.Equal(t, challenge, ao.Challenge)
	assert.Equal(t, state, ao.UserState)
	assert.Equal(t, identifier, ao.UserID)
}
