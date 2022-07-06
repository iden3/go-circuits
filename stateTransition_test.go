package circuits

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"

	it "github.com/iden3/go-circuits/testing"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql"
	"github.com/stretchr/testify/assert"
)

func TestStateTransitionOutput_GetJSONObj(t *testing.T) {
	id, err := core.IDFromString("11AVZrKNJVqDJoyKrdyaAgEynyBEjksV5z2NjZoPxf")
	assert.Nil(t, err)

	newState := hashFromInt(big.NewInt(1))
	oldState := hashFromInt(big.NewInt(2))

	sto := StateTransitionPubSignals{
		UserID:       &id,
		OldUserState: oldState,
		NewUserState: newState,
	}

	m := sto.GetObjMap()
	assert.Equal(t, &id, m["userID"])
	assert.Equal(t, oldState, m["oldUserState"])
	assert.Equal(t, newState, m["newUserState"])

}

func TestStateTransitionIssuerInputs_InputsMarshal(t *testing.T) {
	userPK := "21a5e7321d0e2f3ca1cc6504396e6594a2211544b08c206847cdee96f832421a"
	ctx := context.Background()

	// Issuer
	id, claimsTree, revTree, _, err, authClaim, userPrivKey := it.Generate(ctx,
		userPK)
	assert.Nil(t, err)

	genesisState, err := merkletree.HashElems(
		claimsTree.Root().BigInt(),
		revTree.Root().BigInt(),
		merkletree.HashZero.BigInt())
	assert.Nil(t, err)

	genesisTreeState := TreeState{
		State:          genesisState,
		ClaimsRoot:     claimsTree.Root(),
		RevocationRoot: revTree.Root(),
		RootOfRoots:    &merkletree.HashZero,
	}

	index, err := authClaim.HIndex()
	assert.Nil(t, err)
	authMTPProof, _, err := claimsTree.GenerateProof(ctx, index,
		claimsTree.Root())
	assert.Nil(t, err)

	nonce := new(big.Int).SetUint64(authClaim.GetRevocationNonce())
	authNonRevMTPProof, _, err := revTree.GenerateProof(ctx, nonce,
		revTree.Root())
	assert.Nil(t, err)

	// update rev tree
	//err = revTree.Add(ctx, big.NewInt(1), big.NewInt(0))
	//assert.Nil(t, err)

	stateBigInt, _ := new(big.Int).SetString("17339270624307006522829587570402128825147845744601780689258033623056405933706", 10)

	newState, err := merkletree.NewHashFromBigInt(stateBigInt)
	assert.Nil(t, err)

	//newState, err := merkletree.HashElems(
	//	claimsTree.Root().BigInt(),
	//	revTree.Root().BigInt(),
	//	merkletree.HashZero.BigInt())
	//assert.Nil(t, err)

	// signature
	hashOldAndNewStates, err := poseidon.Hash(
		[]*big.Int{genesisState.BigInt(), newState.BigInt()})
	assert.Nil(t, err)
	signature := userPrivKey.SignPoseidon(hashOldAndNewStates)

	sti := StateTransitionInputs{
		ID:                id,
		OldTreeState:      genesisTreeState,
		NewState:          newState,
		IsOldStateGenesis: true,
		AuthClaim: Claim{
			Claim: authClaim,
			Proof: authMTPProof,
			NonRevProof: &ClaimNonRevStatus{
				Proof: authNonRevMTPProof,
			},
		},
		Signature: signature,
	}

	inputBytes, err := sti.InputsMarshal()
	assert.Nil(t, err)

	//fmt.Println(string(inputBytes))
	expectedJSONInputs := `{"authClaim":["304427537360709784173770334266246861770","0","9582165609074695838007712438814613121302719752874385708394134542816240804696","18271435592817415588213874506882839610978320325722319742324814767882756910515","11203087622270641253","0","0","0"],"authClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtpAuxHi":"0","authClaimNonRevMtpAuxHv":"0","authClaimNonRevMtpNoAux":"1","userID":"26599707002460144379092755370384635496563807452878989192352627271768342528","newUserState":"7569111473237253646417788189126468973900432716598921661470118514516731079797","oldUserState":"6317996369756476782464660619835940615734517981889733696047139451453239145426","isOldStateGenesis":"1","claimsTreeRoot":"18337129644116656308842422695567930755039142442806278977230099338026575870840","revTreeRoot":"0","rootsTreeRoot":"0","signatureR8x":"9484102035827996121666608170002743002783492772260590322761477321381254509037","signatureR8y":"19295134567339498210855406074518612682643335122341225376941332925036431891102","signatureS":"282291664505682519059669624505331509305429004374837545959385601323093440910"}`

	assert.JSONEq(t, expectedJSONInputs, string(inputBytes))

	//generate next state transition

	// update rev tree
	//err = revTree.Add(ctx, big.NewInt(10), big.NewInt(0))
	//assert.Nil(t, err)

	//claimsTreeRootNewState, _ := new(big.Int).SetString("81320939187654552785242505359430863162784295747859591415147129119806281306", 10)
	//claimsTreeHash, err := merkletree.NewHashFromBigInt(claimsTreeRootNewState)
	assert.Nil(t, err)

	indexI, _ := new(big.Int).SetString("9952518973948399855222905667654505135428115441557162018570780317525685263895", 10)
	valueI, _ := new(big.Int).SetString("12984060845532756394764110136147025514383100492807476892974969126577713534395", 10)

	err = claimsTree.Add(ctx, indexI, valueI)
	require.NoError(t, err)

	userNewTreeState := TreeState{
		State:          newState,
		ClaimsRoot:     claimsTree.Root(),
		RevocationRoot: revTree.Root(),
		RootOfRoots:    &merkletree.HashZero,
	}

	authNonRevMTPProofNext, _, err := revTree.GenerateProof(ctx, nonce,
		revTree.Root())

	nextStateBigInt, _ := new(big.Int).SetString("18337129644116656308842422695567930755039142442806278977230099338026575870840", 10)
	nextState, err := merkletree.NewHashFromBigInt(nextStateBigInt)
	assert.Nil(t, err)

	// new signature
	hashNextAndNewStates, err := poseidon.Hash(
		[]*big.Int{newState.BigInt(), nextState.BigInt()})
	assert.Nil(t, err)
	signatureNext := userPrivKey.SignPoseidon(hashNextAndNewStates)

	authMTPProofNext, _, err := claimsTree.GenerateProof(ctx, index,
		claimsTree.Root())
	require.NoError(t, err)

	assert.Nil(t, err)

	stiNext := StateTransitionInputs{
		ID:                id,
		OldTreeState:      userNewTreeState,
		NewState:          nextState,
		IsOldStateGenesis: false,
		AuthClaim: Claim{
			Claim: authClaim,
			Proof: authMTPProofNext,
			NonRevProof: &ClaimNonRevStatus{
				Proof: authNonRevMTPProofNext,
			},
		},
		Signature: signatureNext,
	}
	inputBytesNext, err := stiNext.InputsMarshal()
	assert.Nil(t, err)

	fmt.Println(string(inputBytesNext))
}

func TestStateTransitionUserInputs_InputsMarshal(t *testing.T) {
	userPK := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	ctx := context.Background()

	// Issuer
	id, claimsTree, revTree, _, err, authClaim, userPrivKey := it.Generate(ctx,
		userPK)
	assert.Nil(t, err)

	genesisState, err := merkletree.HashElems(
		claimsTree.Root().BigInt(),
		revTree.Root().BigInt(),
		merkletree.HashZero.BigInt())
	assert.Nil(t, err)

	genesisTreeState := TreeState{
		State:          genesisState,
		ClaimsRoot:     claimsTree.Root(),
		RevocationRoot: revTree.Root(),
		RootOfRoots:    &merkletree.HashZero,
	}

	index, err := authClaim.HIndex()
	assert.Nil(t, err)
	authMTPProof, _, err := claimsTree.GenerateProof(ctx, index,
		claimsTree.Root())
	assert.Nil(t, err)

	nonce := new(big.Int).SetUint64(authClaim.GetRevocationNonce())
	authNonRevMTPProof, _, err := revTree.GenerateProof(ctx, nonce,
		revTree.Root())
	assert.Nil(t, err)

	// update rev tree
	err = revTree.Add(ctx, big.NewInt(10), big.NewInt(0))
	assert.Nil(t, err)

	fmt.Println(genesisState.BigInt().String())
	stateBigInt, _ := new(big.Int).SetString("11660131514240312423013645096623187768802468304351121097689799587038871517788", 10)

	newState, err := merkletree.NewHashFromBigInt(stateBigInt)
	assert.Nil(t, err)

	assert.Nil(t, err)

	//newState, err := merkletree.HashElems(
	//	claimsTree.Root().BigInt(),
	//	revTree.Root().BigInt(),
	//	merkletree.HashZero.BigInt())
	//assert.Nil(t, err)

	// signature
	hashOldAndNewStates, err := poseidon.Hash(
		[]*big.Int{genesisState.BigInt(), newState.BigInt()})
	assert.Nil(t, err)
	signature := userPrivKey.SignPoseidon(hashOldAndNewStates)

	sti := StateTransitionInputs{
		ID:                id,
		OldTreeState:      genesisTreeState,
		NewState:          newState,
		IsOldStateGenesis: true,
		AuthClaim: Claim{
			Claim: authClaim,
			Proof: authMTPProof,
			NonRevProof: &ClaimNonRevStatus{
				Proof: authNonRevMTPProof,
			},
		},
		Signature: signature,
	}

	inputBytes, err := sti.InputsMarshal()
	assert.Nil(t, err)

	fmt.Println(string(inputBytes))
	expectedJSONInputs := `{"authClaim":["304427537360709784173770334266246861770","0","9582165609074695838007712438814613121302719752874385708394134542816240804696","18271435592817415588213874506882839610978320325722319742324814767882756910515","11203087622270641253","0","0","0"],"authClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtpAuxHi":"0","authClaimNonRevMtpAuxHv":"0","authClaimNonRevMtpNoAux":"1","userID":"26599707002460144379092755370384635496563807452878989192352627271768342528","newUserState":"7569111473237253646417788189126468973900432716598921661470118514516731079797","oldUserState":"6317996369756476782464660619835940615734517981889733696047139451453239145426","isOldStateGenesis":"1","claimsTreeRoot":"18337129644116656308842422695567930755039142442806278977230099338026575870840","revTreeRoot":"0","rootsTreeRoot":"0","signatureR8x":"9484102035827996121666608170002743002783492772260590322761477321381254509037","signatureR8y":"19295134567339498210855406074518612682643335122341225376941332925036431891102","signatureS":"282291664505682519059669624505331509305429004374837545959385601323093440910"}`
	assert.JSONEq(t, expectedJSONInputs, string(inputBytes))
}
