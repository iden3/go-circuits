package circuits

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	it "github.com/iden3/go-circuits/v2/testing"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthV2Inputs_InputsMarshal(t *testing.T) {

	ctx := context.Background()
	challenge := big.NewInt(10)

	// generate identity
	user := it.NewIdentity(t, userPK)
	nonce := big.NewInt(0)

	user2 := it.NewIdentity(t, issuerPK)

	// generate gist tree
	gTree := it.GISTTree(ctx)

	err := gTree.Add(ctx, user2.ID.BigInt(), user2.State(t).BigInt())
	require.NoError(t, err)

	// prepare inputs
	gistProof, _, err := gTree.GenerateProof(ctx, user.ID.BigInt(), nil)
	require.NoError(t, err)

	authClaimIncMTP, _ := user.ClaimMTPRaw(t, user.AuthClaim)

	authClaimNonRevMTP, _ := user.ClaimRevMTPRaw(t, user.AuthClaim)
	require.NoError(t, err)

	signature, err := user.SignBBJJ(challenge.Bytes())
	require.NoError(t, err)

	inputs := AuthV2Inputs{
		GenesisID:          &user.ID,
		ProfileNonce:       nonce,
		AuthClaim:          user.AuthClaim,
		AuthClaimIncMtp:    authClaimIncMTP,
		AuthClaimNonRevMtp: authClaimNonRevMTP,
		TreeState:          GetTreeState(t, user),
		GISTProof: GISTProof{
			Root:  gTree.Root(),
			Proof: gistProof,
		},
		Signature: signature,
		Challenge: challenge,
	}

	circuitInputJSON, err := inputs.InputsMarshal()
	assert.Nil(t, err)

	//t.Log(string(circuitInputJSON))
	exp := it.TestData(t, "authV2_inputs", string(circuitInputJSON), *generate)
	require.JSONEq(t, exp, string(circuitInputJSON))
}

func TestAuthV2Inputs_InputsMarshal_fromJson(t *testing.T) {
	t.Skip("skipping TODO: finish test")
	auth2_json := `{
          "id": "119tqceWdRd2F6WnAyVuFQRFjK3WUXq2LorSPyGQoC",
          "nonce": "10",
          "authClaim": {
            "IssuerID": null,
            "Claim": [
              "304427537360709784173770334266246861770",
              "0",
              "17640206035128972995519606214765283372613874593503528180869261482403155458945",
              "20634138280259599560273310290025659992320584624461316485434108770067472477956",
              "15930428023331155902",
              "0",
              "0",
              "0"
            ],
            "IncProof": {
              "proof": {
                "existence": true,
                "siblings": []
              },
              "treeState": {
                "state": "18656147546666944484453899241916469544090258810192803949522794490493271005313",
                "claimsRoot": "9763429684850732628215303952870004997159843236039795272605841029866455670219",
                "revocationRoot": "0",
                "rootOfRoots": "0"
              }
            },
            "NonRevProof": {
              "proof": {
                "existence": false,
                "siblings": []
              },
              "treeState": {
                "state": "18656147546666944484453899241916469544090258810192803949522794490493271005313",
                "claimsRoot": "9763429684850732628215303952870004997159843236039795272605841029866455670219",
                "revocationRoot": "0",
                "rootOfRoots": "0"
              }
            }
          },
          "globalTree": {
            "root": "8654801164827267300505642792609108116741757079309873831472910903288030796079",
            "proof": {
              "existence": false,
              "siblings": [],
              "node_aux": {
                "key": "24225204644786657620626565452898941426026601178354142146799363069935288320",
                "value": "1257746809182882563786560928809910818663538703587513060503018952434273712929"
              }
            }
          },
          "signature": "13274071857accaec43e289504c539812c7b258bb23ce58a4598ad59daf3402eabdf39d356d0d3d2eaac1c983af1f046aa734cfb1d907f7149db32f1e616d502",
          "challenge": "6110517768249559238193477435454792024732173865488900270849624328650765691494"
        }`

	var inputs AuthV2Inputs
	err := json.Unmarshal([]byte(auth2_json), &inputs)
	require.NoError(t, err)

	circuitInputJSON, err := inputs.InputsMarshal()
	require.NoError(t, err)
	//t.Log(string(circuitInputJSON))
	expectedJSONInputs := `{"userGenesisID":"20920305170169595198233610955511031459141100274346276665183631177096036352","nonce":"10","userAuthClaim":["304427537360709784173770334266246861770","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"userAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtpAuxHi":"0","userAuthClaimNonRevMtpAuxHv":"0","userAuthClaimNonRevMtpNoAux":"1","challenge":"6110517768249559238193477435454792024732173865488900270849624328650765691494","challengeSignatureR8x":"2273647433349372574162365571517182161856978101733725351784171216877260126349","challengeSignatureR8y":"20921152258050920729820249883788091534543872328111915977763626674391221282579","challengeSignatureS":"1281122186572874955530253539759994983000852038854525332258204958436946993067","userClaimsTreeRoot":"9763429684850732628215303952870004997159843236039795272605841029866455670219","userRevTreeRoot":"0","userRootsTreeRoot":"0","userState":"18656147546666944484453899241916469544090258810192803949522794490493271005313","globalSmtRoot":"8654801164827267300505642792609108116741757079309873831472910903288030796079","globalSmtMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"globalSmtMtpAuxHi":"24225204644786657620626565452898941426026601178354142146799363069935288320","globalSmtMtpAuxHv":"1257746809182882563786560928809910818663538703587513060503018952434273712929","globalSmtMtpNoAux":"0"}
`
	require.JSONEq(t, expectedJSONInputs, string(circuitInputJSON))
}

func TestAuthV2Circuit_CircuitUnmarshal(t *testing.T) {
	// generate mock Data.
	intID, b := new(big.Int).SetString("19224224881555258540966250468059781351205177043309252290095510834143232000",
		10)
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
	assert.Equal(t, state, ao.GISTRoot)
	assert.Equal(t, &identifier, ao.UserID)
}

func GetTreeState(t *testing.T, it *it.IdentityTest) TreeState {
	return TreeState{
		State:          it.State(t),
		ClaimsRoot:     it.Clt.Root(),
		RevocationRoot: it.Ret.Root(),
		RootOfRoots:    it.Rot.Root(),
	}
}
