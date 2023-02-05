package circuits

import (
	"context"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	it "github.com/iden3/go-circuits/testing"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/stretchr/testify/require"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/stretchr/testify/assert"
)

func TestAtomicQuery_PrepareInputs(t *testing.T) {
	userPrivKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	issuerPrivKHex := "21a5e7321d0e2f3ca1cc6504396e6594a2211544b08c206847cdee96f832421a"
	challenge := new(big.Int).SetInt64(1)
	ctx := context.Background()

	userIdentity, uClaimsTree, uRevsTree, _, err, userAuthCoreClaim, userPrivateKey := it.Generate(ctx,
		userPrivKHex)
	require.NoError(t, err)

	state, err := merkletree.HashElems(
		uClaimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(),
		merkletree.HashZero.BigInt())
	require.NoError(t, err)

	userAuthTreeState := TreeState{
		State:          state,
		ClaimsRoot:     uClaimsTree.Root(),
		RevocationRoot: &merkletree.HashZero,
		RootOfRoots:    &merkletree.HashZero,
	}

	hIndexAuthEntryUser, _, err := claimsIndexValueHashes(*userAuthCoreClaim)
	require.NoError(t, err)

	mtpProofUser, _, err := uClaimsTree.GenerateProof(ctx,
		hIndexAuthEntryUser, uClaimsTree.Root())
	require.NoError(t, err)

	// TODO why not swapped?
	message := big.NewInt(0).SetBytes(challenge.Bytes())

	challengeSignature := userPrivateKey.SignPoseidon(message)

	// Issuer
	issuerID, iClaimsTree, _, _, err, _, _ := it.Generate(ctx, issuerPrivKHex)
	require.NoError(t, err)

	// issue issuerClaim for user
	dataSlotA, err := core.NewElemBytesFromInt(big.NewInt(10))
	require.NoError(t, err)

	nonce := 1
	var schemaHash core.SchemaHash

	schemaBytes, err := hex.DecodeString("ce6bb12c96bfd1544c02c289c6b4b987")
	require.NoError(t, err)

	copy(schemaHash[:], schemaBytes)

	issuerCoreClaim, err := core.NewClaim(
		schemaHash,
		core.WithIndexID(*userIdentity),
		core.WithIndexData(dataSlotA, core.ElemBytes{}),
		core.WithExpirationDate(time.Unix(1669884010,
			0)), //Thu Dec 01 2022 08:40:10 GMT+0000
		core.WithRevocationNonce(uint64(nonce)))
	require.NoError(t, err)

	hIndexClaimEntry, hValueClaimEntry, err := claimsIndexValueHashes(*issuerCoreClaim)
	require.NoError(t, err)

	err = iClaimsTree.Add(ctx, hIndexClaimEntry, hValueClaimEntry)
	require.NoError(t, err)

	proof, _, err := iClaimsTree.GenerateProof(ctx, hIndexClaimEntry,
		iClaimsTree.Root())
	require.NoError(t, err)

	stateAfterClaimAdd, err := merkletree.HashElems(
		iClaimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(),
		merkletree.HashZero.BigInt())
	require.NoError(t, err)

	issuerStateAfterClaimAdd := TreeState{
		State:          stateAfterClaimAdd,
		ClaimsRoot:     iClaimsTree.Root(),
		RevocationRoot: &merkletree.HashZero,
		RootOfRoots:    &merkletree.HashZero,
	}

	issuerRevTreeStorage := memory.NewMemoryStorage()
	issuerRevTree, err := merkletree.NewMerkleTree(ctx, issuerRevTreeStorage,
		40)
	require.NoError(t, err)

	proofNotRevoke, _, err := issuerRevTree.GenerateProof(ctx,
		big.NewInt(int64(nonce)), nil)
	require.NoError(t, err)

	authClaimRevNonce := new(big.Int).
		SetUint64(userAuthCoreClaim.GetRevocationNonce())
	proofAuthClaimNotRevoked, _, err :=
		uRevsTree.GenerateProof(ctx, authClaimRevNonce, nil)
	require.NoError(t, err)

	inputsAuthClaim := ClaimWithMTPProof{
		Claim: userAuthCoreClaim,
		IncProof: MTProof{
			Proof:     mtpProofUser,
			TreeState: userAuthTreeState,
		},
		NonRevProof: MTProof{
			TreeState: userAuthTreeState,
			Proof:     proofAuthClaimNotRevoked,
		},
	}

	inputsUserClaim := ClaimWithMTPProof{
		Claim: issuerCoreClaim,
		IncProof: MTProof{
			Proof:     proof,
			TreeState: issuerStateAfterClaimAdd,
		},
		IssuerID: issuerID,
		NonRevProof: MTProof{
			TreeState: issuerStateAfterClaimAdd,
			Proof:     proofNotRevoke,
		},
	}

	query := Query{
		SlotIndex: 2,
		Values:    []*big.Int{new(big.Int).SetInt64(10)},
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
		BaseConfig: BaseConfig{
			MTLevel: 32,
		},
	}

	bytesInputs, err := atomicInputs.InputsMarshal()
	require.NoError(t, err)
	expectedJSONInputs := `{"userAuthClaim":["304427537360709784173770334266246861770","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"userAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtpAuxHi":"0","userAuthClaimNonRevMtpAuxHv":"0","userAuthClaimNonRevMtpNoAux":"1","userClaimsTreeRoot":"9763429684850732628215303952870004997159843236039795272605841029866455670219","userState":"18656147546666944484453899241916469544090258810192803949522794490493271005313","userRevTreeRoot":"0","userRootsTreeRoot":"0","userID":"20920305170169595198233610955511031459141100274346276665183631177096036352","challenge":"1","challengeSignatureR8x":"8553678144208642175027223770335048072652078621216414881653012537434846327449","challengeSignatureR8y":"5507837342589329113352496188906367161790372084365285966741761856353367255709","challengeSignatureS":"2093461910575977345603199789919760192811763972089699387324401771367839603655","issuerClaim":["3583233690122716044519380227940806650830","20920305170169595198233610955511031459141100274346276665183631177096036352","10","0","30803922965249841627828060161","0","0","0"],"issuerClaimClaimsTreeRoot":"9039420820783947225129721782217789545748472394427426963935402963755305583703","issuerClaimIdenState":"13502509003951168747865850207840147567848114437663919718666503371668245440139","issuerClaimMtp":["0","18337129644116656308842422695567930755039142442806278977230099338026575870840","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimRevTreeRoot":"0","issuerClaimRootsTreeRoot":"0","issuerClaimNonRevClaimsTreeRoot":"9039420820783947225129721782217789545748472394427426963935402963755305583703","issuerClaimNonRevRevTreeRoot":"0","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"13502509003951168747865850207840147567848114437663919718666503371668245440139","issuerClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"0","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"1","claimSchema":"180410020913331409885634153623124536270","issuerID":"24839761684028550613296892625503994006188774664975540620786183594699522048","operator":1,"slotIndex":2,"timestamp":"1642074362","value":["10","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]}`

	require.JSONEq(t, expectedJSONInputs, string(bytesInputs))

}

func TestAtomicQueryMTPOutputs_CircuitUnmarshal(t *testing.T) {

	userID, err := idFromIntStr("19224224881555258540966250468059781351205177043309252290095510834143232000")
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

	issuerID, err := idFromIntStr("19224224881555258540966250468059781351205177043309252290095510834143232000")
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
		`["19224224881555258540966250468059781351205177043309252290095510834143232000", 
"18656147546666944484453899241916469544090258810192803949522794490493271005313", "1", 
"18605292738057394742004097311192572049290380262377486632479765119429313092475", "19224224881555258540966250468059781351205177043309252290095510834143232000", "4526669839764419626617575537226877836118875794723391624256342150634803457675","1642074362", "180410020913331409885634153623124536270", "2", "1", "10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "9999"]`))
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
