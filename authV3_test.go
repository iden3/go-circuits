package circuits

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	it "github.com/iden3/go-circuits/v2/testing"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/stretchr/testify/require"
)

func authV3Inputs(t testing.TB, isAuthV3_8_32 bool) AuthV3Inputs {
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

	inputs := AuthV3Inputs{
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

	if isAuthV3_8_32 {
		inputs.BaseConfig = BaseConfig{MTLevel: 8, MTLevelOnChain: 32}
	}
	return inputs
}

func TestAuthV3Inputs_InputsMarshal(t *testing.T) {
	inputs := authV3Inputs(t, false)
	circuitInputJSON, err := inputs.InputsMarshal()
	require.NoError(t, err)

	exp := it.TestData(t, "authV3_inputs", string(circuitInputJSON), *generate)
	require.JSONEq(t, exp, string(circuitInputJSON))
}

func TestAuthV3_8_32Inputs_InputsMarshal(t *testing.T) {
	inputs := authV3Inputs(t, true)
	circuitInputJSON, err := inputs.InputsMarshal()
	require.NoError(t, err)

	exp := it.TestData(t, "authV3-8-32_inputs", string(circuitInputJSON), *generate)
	require.JSONEq(t, exp, string(circuitInputJSON))
}

func TestAuthV3Inputs_GetPublicStatesInfo(t *testing.T) {
	inputs := authV3Inputs(t, false)
	statesInfo, err := inputs.GetPublicStatesInfo()
	require.NoError(t, err)

	statesInfoJsonBytes, err := json.Marshal(statesInfo)
	require.NoError(t, err)

	want := `{
	"states":[],
	"gists":[
			{
			"id":"26109404700696283154998654512117952420503675471097392618762221546565140481",
			"root":"11098939821764568131087645431296528907277253709936443029379587475821759259406"
			}
		]
	}`

	require.JSONEq(t, want, string(statesInfoJsonBytes))
}

func TestAuthV3_8_32Inputs_GetPublicStatesInfo(t *testing.T) {
	inputs := authV3Inputs(t, true)
	statesInfo, err := inputs.GetPublicStatesInfo()
	require.NoError(t, err)

	statesInfoJsonBytes, err := json.Marshal(statesInfo)
	require.NoError(t, err)

	want := `{
	"states":[],
	"gists":[
			{
			"id":"26109404700696283154998654512117952420503675471097392618762221546565140481",
			"root":"11098939821764568131087645431296528907277253709936443029379587475821759259406"
			}
		]
	}`

	require.JSONEq(t, want, string(statesInfoJsonBytes))
}

func TestAuthV3Circuit_CircuitUnmarshal(t *testing.T) {
	// generate mock Data.
	intID, b := new(big.Int).SetString("19224224881555258540966250468059781351205177043309252290095510834143232000",
		10)
	require.True(t, b)
	identifier, err := core.IDFromInt(intID)
	require.NoError(t, err)

	challenge := big.NewInt(1)

	stateInt, b := new(big.Int).SetString(
		"18656147546666944484453899241916469544090258810192803949522794490493271005313",
		10)
	require.True(t, b)
	state, err := merkletree.NewHashFromBigInt(stateInt)
	require.NoError(t, err)

	out := []string{identifier.BigInt().String(), challenge.String(), state.BigInt().String()}
	bytesOut, err := json.Marshal(out)
	require.NoError(t, err)

	ao := AuthV3PubSignals{}
	err = ao.PubSignalsUnmarshal(bytesOut)
	require.NoError(t, err)
	require.Equal(t, challenge, ao.Challenge)
	require.Equal(t, state, ao.GISTRoot)
	require.Equal(t, &identifier, ao.UserID)

	statesInfo, err := ao.GetStatesInfo()
	require.NoError(t, err)
	wantStatesInfo := StatesInfo{
		States: []State{},
		Gists: []Gist{
			{
				ID:   idFromInt("19224224881555258540966250468059781351205177043309252290095510834143232000"),
				Root: hashFromInt("18656147546666944484453899241916469544090258810192803949522794490493271005313"),
			},
		},
	}
	j, err := json.Marshal(statesInfo)
	require.NoError(t, err)
	require.Equal(t, wantStatesInfo, statesInfo, string(j))
}

func TestAuthV3Inputs_JsonMarshal(t *testing.T) {
	inputs := authV3Inputs(t, false)
	inputsJson, err := json.Marshal(inputs)
	require.NoError(t, err)
	want := `
{
  "authClaim" : [
    "80551937543569765027552589160822318028",
    "0",
    "17640206035128972995519606214765283372613874593503528180869261482403155458945",
    "20634138280259599560273310290025659992320584624461316485434108770067472477956",
    "15930428023331155902",
    "0",
    "0",
    "0"
  ],
  "authClaimIncMtp" : { "existence" : true, "siblings" : [] },
  "authClaimNonRevMtp" : { "existence" : false, "siblings" : [ ] },
  "challenge" : "10",
  "genesisID" : "tQomzpDTB6x4EJUaiwk153FVi96jeNfP9WjKp9xys",
  "gistProof" : {
    "proof" : {
      "existence" : false,
      "node_aux" : {
        "key" : "27918766665310231445021466320959318414450284884582375163563581940319453185",
        "value" : "20177832565449474772630743317224985532862797657496372535616634430055981993180"
      },
      "siblings" : [ ]
    },
    "root" : "11098939821764568131087645431296528907277253709936443029379587475821759259406"
  },
  "profileNonce" : "0",
  "signature" : "fccc15d7aed2bf4f5d7dbe55c81087970344d13e5d9f348e61965ac364f41d29b366b52bc0820c603877352054833da083f5595c29c881ccd8ee47aa639aa103",
  "treeState" : {
    "claimsRoot" : "9860409408344985873118363460916733946840214387455464863344022463808838582364",
    "revocationRoot" : "0",
    "rootOfRoots" : "0",
    "state" : "1648710229725601204870171311149827592640182384459240511403224642152766848235"
  }
}`
	require.JSONEq(t, want, string(inputsJson))
}
