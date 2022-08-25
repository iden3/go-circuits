package circuits

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	it "github.com/iden3/go-circuits/testing"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/require"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
	"github.com/stretchr/testify/assert"
)

func TestAtomicQuery_PrepareInputs(t *testing.T) {
	userPrivKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	issuerPrivKHex := "21a5e7321d0e2f3ca1cc6504396e6594a2211544b08c206847cdee96f832421a"
	challenge := new(big.Int).SetInt64(1)
	ctx := context.Background()

	userIdentity, uClaimsTree, uRevsTree, _, err, userAuthCoreClaim, userPrivateKey := it.Generate(ctx,
		userPrivKHex)
	assert.Nil(t, err)
	fmt.Println(userIdentity.String())

	state, err := merkletree.HashElems(
		uClaimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(),
		merkletree.HashZero.BigInt())
	assert.Nil(t, err)

	_ = TreeState{
		State:          state,
		ClaimsRoot:     uClaimsTree.Root(),
		RevocationRoot: &merkletree.HashZero,
		RootOfRoots:    &merkletree.HashZero,
	}

	fmt.Println("genesis user state: ", state.BigInt())

	/*
		Add claim to user state
	*/

	err = uRevsTree.Add(ctx, new(big.Int).SetInt64(10), new(big.Int).SetInt64(0))
	assert.NoError(t, err)
	fmt.Println("revocation root new", uRevsTree.Root().Hex())

	// for new user state

	newUserState, err := merkletree.HashElems(
		uClaimsTree.Root().BigInt(),
		uRevsTree.Root().BigInt(),
		merkletree.HashZero.BigInt())
	assert.Nil(t, err)

	userNewTreeState := TreeState{
		State:          newUserState,
		ClaimsRoot:     uClaimsTree.Root(),
		RevocationRoot: uRevsTree.Root(),
		RootOfRoots:    &merkletree.HashZero,
	}
	fmt.Println("new user state: ", newUserState.BigInt().String())

	hIndexAuthEntryUser, _, err := claimsIndexValueHashes(*userAuthCoreClaim)
	require.NoError(t, err)

	mtpProofUser, _, err := uClaimsTree.GenerateProof(ctx,
		hIndexAuthEntryUser, uClaimsTree.Root())
	assert.Nil(t, err)

	message := big.NewInt(0).SetBytes(challenge.Bytes())

	challengeSignature := userPrivateKey.SignPoseidon(message)

	// Issuer
	issuerID, iClaimsTree, _, _, err, _, _ := it.Generate(ctx,
		issuerPrivKHex)
	assert.Nil(t, err)

	// issue issuerClaim for user
	dataSlotA, err := core.NewElemBytesFromInt(big.NewInt(980))
	assert.Nil(t, err)
	dataSlotB, err := core.NewElemBytesFromInt(big.NewInt(1))
	assert.Nil(t, err)

	nonce := 1
	var schemaHash core.SchemaHash

	schemaBytes, err := hex.DecodeString("ce38102464833febf36e714922a83050")
	assert.Nil(t, err)

	copy(schemaHash[:], schemaBytes)

	issuerCoreClaim, err := core.NewClaim(
		schemaHash,
		core.WithIndexID(*userIdentity),
		core.WithIndexData(dataSlotA, dataSlotB),
		core.WithExpirationDate(time.Unix(1669884010,
			0)), //Thu Dec 01 2022 08:40:10 GMT+0000
		core.WithRevocationNonce(uint64(nonce)))
	assert.Nil(t, err)

	hIndexClaimEntry, hValueClaimEntry, err := claimsIndexValueHashes(*issuerCoreClaim)
	require.NoError(t, err)

	fmt.Println(hIndexClaimEntry.String())
	fmt.Println(hValueClaimEntry.String())

	err = iClaimsTree.Add(ctx, hIndexClaimEntry, hValueClaimEntry)
	require.NoError(t, err)

	proof, _, err := iClaimsTree.GenerateProof(ctx, hIndexClaimEntry,
		iClaimsTree.Root())
	assert.Nil(t, err)

	stateAfterClaimAdd, err := merkletree.HashElems(
		iClaimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(),
		merkletree.HashZero.BigInt())
	assert.Nil(t, err)
	fmt.Println("++++++")
	fmt.Println(stateAfterClaimAdd.BigInt().String())
	fmt.Println(iClaimsTree.Root().BigInt().String())

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

	authClaimRevNonce := new(big.Int).
		SetUint64(userAuthCoreClaim.GetRevocationNonce())
	proofAuthClaimNotRevoked, _, err :=
		uRevsTree.GenerateProof(ctx, authClaimRevNonce, uRevsTree.Root())
	require.NoError(t, err)

	te := time.Unix(1642074362, 0).Unix()
	fmt.Println(te)
	inputsAuthClaim := Claim{
		Claim:     userAuthCoreClaim,
		Proof:     mtpProofUser,
		TreeState: userNewTreeState,
		NonRevProof: &ClaimNonRevStatus{
			TreeState: userNewTreeState,
			Proof:     proofAuthClaimNotRevoked,
		},
	}

	inputsUserClaim := Claim{
		Claim:     issuerCoreClaim,
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
		Values:    []*big.Int{big.NewInt(980)},
		Operator:  EQ,
	}

	atomicInputs := AtomicQueryMTPInputs{
		ID:        userIdentity,
		AuthClaim: inputsAuthClaim,
		Challenge: challenge,
		Signature: challengeSignature,

		Claim: inputsUserClaim,

		CurrentTimeStamp: time.Unix(1642074362, 0).Unix(),

		Query: query,
	}

	bytesInputs, err := atomicInputs.InputsMarshal()
	assert.Nil(t, err)

	fmt.Println(string(bytesInputs))
	expectedJSONInputs := `{ "userAuthClaim": [ "304427537360709784173770334266246861770", "0","17640206035128972995519606214765283372613874593503528180869261482403155458945", "20634138280259599560273310290025659992320584624461316485434108770067472477956", "15930428023331155902", "0", "0", "0" ], "userAuthClaimMtp": [ "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0" ], "userAuthClaimNonRevMtp": [ "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0" ], "userAuthClaimNonRevMtpAuxHi": "0", "userAuthClaimNonRevMtpAuxHv": "0", "userAuthClaimNonRevMtpNoAux": "1", "userClaimsTreeRoot": "9763429684850732628215303952870004997159843236039795272605841029866455670219", "userState": "18656147546666944484453899241916469544090258810192803949522794490493271005313", "userRevTreeRoot": "0", "userRootsTreeRoot": "0", "userID": "379949150130214723420589610911161895495647789006649785264738141299135414272", "challenge": "1", "challengeSignatureR8x": "8553678144208642175027223770335048072652078621216414881653012537434846327449", "challengeSignatureR8y":"5507837342589329113352496188906367161790372084365285966741761856353367255709", "challengeSignatureS": "2093461910575977345603199789919760192811763972089699387324401771367839603655", "issuerClaim": [ "3583233690122716044519380227940806650830", "379949150130214723420589610911161895495647789006649785264738141299135414272", "10", "0", "30803922965249841627828060161", "0", "0", "0" ], "issuerClaimClaimsTreeRoot": "3077200351284676204723270374054827783313480677490603169533924119235084704890", "issuerClaimIdenState": "18605292738057394742004097311192572049290380262377486632479765119429313092475", "issuerClaimMtp": [ "0", "0", "18337129644116656308842422695567930755039142442806278977230099338026575870840", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0" ], "issuerClaimRevTreeRoot": "0", "issuerClaimRootsTreeRoot": "0", "issuerClaimNonRevClaimsTreeRoot": "3077200351284676204723270374054827783313480677490603169533924119235084704890", "issuerClaimNonRevRevTreeRoot": "0", "issuerClaimNonRevRootsTreeRoot": "0", "issuerClaimNonRevState": "18605292738057394742004097311192572049290380262377486632479765119429313092475", "issuerClaimNonRevMtp": [ "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0" ], "issuerClaimNonRevMtpAuxHi": "0", "issuerClaimNonRevMtpAuxHv": "0", "issuerClaimNonRevMtpNoAux": "1", "claimSchema": "180410020913331409885634153623124536270", "issuerID": "26599707002460144379092755370384635496563807452878989192352627271768342528", "operator": 1, "slotIndex": 2, "timestamp": "1642074362", "value": [ "10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0" ] }`

	assert.JSONEq(t, expectedJSONInputs, string(bytesInputs))

}

func TestAtomicQueryMTPOutputs_CircuitUnmarshal(t *testing.T) {

	userID, err := idFromIntStr("379949150130214723420589610911161895495647789006649785264738141299135414272")
	assert.NoError(t, err)

	userStateInt, ok := new(big.Int).SetString(
		"18656147546666944484453899241916469544090258810192803949522794490493271005313", 10)
	assert.True(t, ok)
	userState, err := merkletree.NewHashFromBigInt(userStateInt)
	assert.NoError(t, err)

	schemaInt, ok := new(big.Int).SetString("180410020913331409885634153623124536270", 10)
	assert.True(t, ok)
	schema := core.NewSchemaHashFromInt(schemaInt)

	issuerClaimIdenStateInt, ok := new(big.Int).SetString("18605292738057394742004097311192572049290380262377486632479765119429313092475", 10)
	assert.True(t, ok)
	issuerClaimIdenState, err := merkletree.NewHashFromBigInt(issuerClaimIdenStateInt)
	assert.NoError(t, err)

	issuerClaimNonRevStateInt, ok := new(big.Int).SetString("4526669839764419626617575537226877836118875794723391624256342150634803457675", 10)
	assert.True(t, ok)
	issuerClaimNonRevState, err := merkletree.NewHashFromBigInt(issuerClaimNonRevStateInt)
	assert.NoError(t, err)

	issuerID, err := idFromIntStr("26599707002460144379092755370384635496563807452878989192352627271768342528")
	assert.NoError(t, err)

	values := make([]*big.Int, 64)
	for i := 0; i < 64; i++ {
		values[i] = big.NewInt(0)
	}
	values[0].SetInt64(10)
	values[63].SetInt64(9999)

	timestamp := int64(1642074362)

	expectedOut := AtomicQueryMTPPubSignals{
		UserID:                 userID,
		UserState:              userState,
		Challenge:              big.NewInt(1),
		ClaimSchema:            schema,
		IssuerClaimIdenState:   issuerClaimIdenState,
		IssuerClaimNonRevState: issuerClaimNonRevState,
		IssuerID:               issuerID,
		SlotIndex:              2,
		Values:                 values,
		Operator:               EQ,
		Timestamp:              timestamp,
	}

	out := new(AtomicQueryMTPPubSignals)
	err = out.PubSignalsUnmarshal([]byte(
		`["379949150130214723420589610911161895495647789006649785264738141299135414272", 
"18656147546666944484453899241916469544090258810192803949522794490493271005313", "1", 
"18605292738057394742004097311192572049290380262377486632479765119429313092475", "26599707002460144379092755370384635496563807452878989192352627271768342528", "4526669839764419626617575537226877836118875794723391624256342150634803457675","1642074362", "180410020913331409885634153623124536270", "2", "1", "10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "9999"]`))
	assert.NoError(t, err)

	assert.Equal(t, expectedOut, *out)

}

func claimsIndexValueHashes(c core.Claim) (*big.Int, *big.Int, error) {
	index, value := c.RawSlots()
	indexHash, err := poseidon.Hash(core.ElemBytesToInts(index[:]))
	if err != nil {
		return nil, nil, err
	}
	valueHash, err := poseidon.Hash(core.ElemBytesToInts(value[:]))
	return indexHash, valueHash, err
}
