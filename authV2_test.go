package circuits

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	it "github.com/iden3/go-circuits/testing"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql"
	"github.com/stretchr/testify/assert"
)

func TestAuthV2Inputs_InputsMarshal(t *testing.T) {
	ctx := context.Background()
	privKeyHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	challenge, b := big.NewInt(0).SetString(
		"6110517768249559238193477435454792024732173865488900270849624328650765691494", 10) // hash("mymessage")
	assert.True(t, b)
	identifier, claim, state, claimsTree, revTree, rootsTree, claimEntryMTP, claimNonRevMTP, signature, err := it.AuthClaimFullInfo(ctx, privKeyHex, challenge)
	assert.Nil(t, err)

	gTree := it.GlobalTree(ctx)

	// add id to global tree
	h := "a65ddf87d7f064d8306833149a42f0ec260533cb9e7f0e8493a796114ce979b9"
	i, _, s, _, _, _, _, _, _, err := it.AuthClaimFullInfo(ctx, h, challenge)
	gTree.Add(ctx, i.BigInt(), s.BigInt())

	// Generate proof
	proof, _, err := gTree.GenerateProof(ctx, identifier.BigInt(), nil)
	assert.NoError(t, err)

	treeState := TreeState{
		State:          state,
		ClaimsRoot:     claimsTree.Root(),
		RevocationRoot: revTree.Root(),
		RootOfRoots:    rootsTree.Root(),
	}

	globalTree := GlobalTree{
		Root:  gTree.Root(),
		Proof: proof,
	}

	inputs := AuthV2Inputs{
		ID:   identifier,
		Salt: big.NewInt(10),
		AuthClaim: ClaimV2{
			Claim: claim,
			MTProof: MTProof{
				Proof:     claimEntryMTP,
				TreeState: treeState,
			},
			NonRevProof: ClaimNonRevStatus{treeState, claimNonRevMTP},
			GlobalTree:  globalTree,
		},
		Signature: signature,
		Challenge: challenge,
	}

	circuitInputJSON, err := inputs.InputsMarshal()
	assert.Nil(t, err)
	t.Log(string(circuitInputJSON))
	expectedJSONInputs := `{"userGenesisID":"379949150130214723420589610911161895495647789006649785264738141299135414272","userSalt":"10","userAuthClaim":["304427537360709784173770334266246861770","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"userAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtpAuxHi":"0","userAuthClaimNonRevMtpAuxHv":"0","userAuthClaimNonRevMtpNoAux":"1","challenge":"6110517768249559238193477435454792024732173865488900270849624328650765691494","challengeSignatureR8x":"2273647433349372574162365571517182161856978101733725351784171216877260126349","challengeSignatureR8y":"20921152258050920729820249883788091534543872328111915977763626674391221282579","challengeSignatureS":"1281122186572874955530253539759994983000852038854525332258204958436946993067","userClaimsTreeRoot":"9763429684850732628215303952870004997159843236039795272605841029866455670219","userRevTreeRoot":"0","userRootsTreeRoot":"0","userState":"18656147546666944484453899241916469544090258810192803949522794490493271005313","globalSmtRoot":"13891407091237035626910338386637210028103224489833886255774452947213913989795","globalSmtMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"globalSmtMtpAuxHi":"321655963459726004040127369337727353299407142334036950741528344494565949440","globalSmtMtpAuxHv":"1257746809182882563786560928809910818663538703587513060503018952434273712929","globalSmtMtpNoAux":"0"}
`

	var actualInputs map[string]interface{}
	err = json.Unmarshal(circuitInputJSON, &actualInputs)
	assert.Nil(t, err)

	var expectedInputs map[string]interface{}
	err = json.Unmarshal([]byte(expectedJSONInputs), &expectedInputs)
	assert.Nil(t, err)

	assert.Equal(t, actualInputs, expectedInputs)
}

func TestAuthV2Circuit_CircuitUnmarshal(t *testing.T) {
	// generate mock Data.
	intID, b := new(big.Int).SetString("86673097869291892577577670655095803058458914610818194234435166934839525376", 10)
	assert.True(t, b)
	identifier, err := core.IDFromInt(intID)
	assert.Nil(t, err)

	challenge := big.NewInt(1)

	stateInt, b := new(big.Int).SetString(
		"18656147546666944484453899241916469544090258810192803949522794490493271005313",
		10)
	assert.True(t, b)
	state, err := merkletree.NewHashFromBigInt(stateInt)
	assert.NoError(t, err)

	out := []string{identifier.BigInt().String(), challenge.String(), state.BigInt().String()}
	bytesOut, err := json.Marshal(out)
	assert.NoError(t, err)

	ao := AuthV2PubSignals{}
	err = ao.PubSignalsUnmarshal(bytesOut)
	assert.NoError(t, err)
	assert.Equal(t, challenge, ao.Challenge)
	assert.Equal(t, state, ao.GlobalRoot)
	assert.Equal(t, &identifier, ao.UserID)
}
