package circuits

import (
	"context"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	it "github.com/iden3/go-circuits/testing"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/stretchr/testify/require"
)

func TestAttrQuerySig_PrepareInputs(t *testing.T) {
	userPrivKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	issuerPrivKHex := "21a5e7321d0e2f3ca1cc6504396e6594a2211544b08c206847cdee96f832421a"
	challenge := new(big.Int).SetInt64(1)
	ctx := context.Background()

	userIdentity, uClaimsTree, _, _, err, userAuthCoreClaim, userPrivateKey := it.Generate(ctx,
		userPrivKHex)
	require.Nil(t, err)

	state, err := merkletree.HashElems(
		uClaimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(),
		merkletree.HashZero.BigInt())

	userAuthTreeState := TreeState{
		State:          state,
		ClaimsRoot:     uClaimsTree.Root(),
		RevocationRoot: &merkletree.HashZero,
		RootOfRoots:    &merkletree.HashZero,
	}
	require.Nil(t, err)

	hIndexAuthEntryUser, _, err := claimsIndexValueHashes(*userAuthCoreClaim)
	require.Nil(t, err)

	mtpProofUser, _, err := uClaimsTree.GenerateProof(ctx,
		hIndexAuthEntryUser, uClaimsTree.Root())
	require.Nil(t, err)

	message := big.NewInt(0).SetBytes(challenge.Bytes())

	challengeSignature := userPrivateKey.SignPoseidon(message)

	// Issuer
	issuerIdentity, iClaimsTree, iRevTree, _, err, issuerAuthClaim, issuerKey := it.Generate(ctx,
		issuerPrivKHex)
	require.Nil(t, err)

	// issuer state
	issuerGenesisState, err := merkletree.HashElems(
		iClaimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(),
		merkletree.HashZero.BigInt())
	require.NoError(t, err)

	issuerAuthTreeState := TreeState{
		State:          issuerGenesisState,
		ClaimsRoot:     iClaimsTree.Root(),
		RevocationRoot: &merkletree.HashZero,
		RootOfRoots:    &merkletree.HashZero,
	}

	hIndexAuthEntryIssuer, _, err :=
		claimsIndexValueHashes(*issuerAuthClaim)
	require.NoError(t, err)

	mtpProofIssuer, _, err := iClaimsTree.GenerateProof(ctx,
		hIndexAuthEntryIssuer, iClaimsTree.Root())
	require.Nil(t, err)

	issuerAuthClaimRevNonce := new(big.Int).SetUint64(issuerAuthClaim.GetRevocationNonce())
	issuerAuthNonRevProof, _, err := iRevTree.GenerateProof(ctx,
		issuerAuthClaimRevNonce, iRevTree.Root())
	require.Nil(t, err)

	// issue issuerClaim for user
	dataSlotA, err := core.NewElemBytesFromInt(big.NewInt(10))
	require.Nil(t, err)

	nonce := 1
	var schemaHash core.SchemaHash

	schemaBytes, err := hex.DecodeString("ce6bb12c96bfd1544c02c289c6b4b987")
	require.Nil(t, err)

	copy(schemaHash[:], schemaBytes)

	issuerCoreClaim, err := core.NewClaim(
		schemaHash,
		core.WithIndexID(*userIdentity),
		core.WithIndexData(dataSlotA, core.ElemBytes{}),
		core.WithExpirationDate(time.Unix(1669884010,
			0)), //Thu Dec 01 2022 08:40:10 GMT+0000
		core.WithRevocationNonce(uint64(nonce)))
	require.Nil(t, err)

	hashIndex, hashValue, err := claimsIndexValueHashes(*issuerCoreClaim)
	require.Nil(t, err)

	commonHash, err := merkletree.HashElems(hashIndex, hashValue)
	require.NoError(t, err)

	claimSignature := issuerKey.SignPoseidon(commonHash.BigInt())

	err = iClaimsTree.Add(ctx, hashIndex, hashValue)
	require.Nil(t, err)

	stateAfterClaimAdd, err := merkletree.HashElems(
		iClaimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(),
		merkletree.HashZero.BigInt())
	require.Nil(t, err)

	issuerStateAfterClaimAdd := TreeState{
		State:          stateAfterClaimAdd,
		ClaimsRoot:     iClaimsTree.Root(),
		RevocationRoot: &merkletree.HashZero,
		RootOfRoots:    &merkletree.HashZero,
	}

	issuerRevTreeStorage := memory.NewMemoryStorage()
	issuerRevTree, err := merkletree.NewMerkleTree(ctx, issuerRevTreeStorage,
		40)
	require.Nil(t, err)

	proofNotRevoke, _, err := issuerRevTree.GenerateProof(ctx,
		big.NewInt(int64(nonce)), issuerRevTree.Root())
	require.Nil(t, err)

	inputsAuthClaim := ClaimWithMTPProof{
		//Schema:    authClaim.Schema,
		Claim: userAuthCoreClaim,
		IncProof: MTProof{
			Proof:     mtpProofUser,
			TreeState: userAuthTreeState,
		},
		NonRevProof: MTProof{
			TreeState: userAuthTreeState,
			Proof:     mtpProofUser,
		},
	}

	claimIssuerSignature := BJJSignatureProof{
		Signature:       claimSignature,
		IssuerAuthClaim: issuerAuthClaim,
		IssuerAuthIncProof: MTProof{
			TreeState: issuerAuthTreeState,
			Proof:     mtpProofIssuer,
		},
		IssuerAuthNonRevProof: MTProof{
			TreeState: issuerAuthTreeState,
			Proof:     issuerAuthNonRevProof,
		},
	}

	inputsUserClaim := ClaimWithSigProof{
		Claim: issuerCoreClaim,
		//TreeState: issuerStateAfterClaimAdd,
		NonRevProof: MTProof{
			TreeState: issuerStateAfterClaimAdd,
			Proof:     proofNotRevoke,
		},
		IssuerID:       issuerIdentity,
		SignatureProof: claimIssuerSignature,
	}

	query := Query{
		SlotIndex: 2,
		Values:    []*big.Int{new(big.Int).SetInt64(10)},
		Operator:  EQ,
	}

	atomicInputs := AtomicQuerySigInputs{
		ID:        userIdentity,
		AuthClaim: inputsAuthClaim,
		Challenge: challenge,
		Signature: challengeSignature,

		CurrentTimeStamp: time.Unix(1642074362, 0).Unix(),

		Claim: inputsUserClaim,

		Query:      query,
		BaseConfig: BaseConfig{MTLevel: 32},
	}

	bytesInputs, err := atomicInputs.InputsMarshal()
	require.Nil(t, err)

	t.Log(string(bytesInputs))
	expectedJSONInputs := `{"userAuthClaim":["304427537360709784173770334266246861770","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"userAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtpAuxHi":"0","userAuthClaimNonRevMtpAuxHv":"0","userAuthClaimNonRevMtpNoAux":"0","userClaimsTreeRoot":"9763429684850732628215303952870004997159843236039795272605841029866455670219","userState":"18656147546666944484453899241916469544090258810192803949522794490493271005313","userRevTreeRoot":"0","userRootsTreeRoot":"0","userID":"20920305170169595198233610955511031459141100274346276665183631177096036352","challenge":"1","challengeSignatureR8x":"8553678144208642175027223770335048072652078621216414881653012537434846327449","challengeSignatureR8y":"5507837342589329113352496188906367161790372084365285966741761856353367255709","challengeSignatureS":"2093461910575977345603199789919760192811763972089699387324401771367839603655","issuerClaim":["3583233690122716044519380227940806650830","20920305170169595198233610955511031459141100274346276665183631177096036352","10","0","30803922965249841627828060161","0","0","0"],"issuerClaimNonRevClaimsTreeRoot":"9039420820783947225129721782217789545748472394427426963935402963755305583703","issuerClaimNonRevRevTreeRoot":"0","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"13502509003951168747865850207840147567848114437663919718666503371668245440139","issuerClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"0","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"1","claimSchema":"180410020913331409885634153623124536270","issuerID":"24839761684028550613296892625503994006188774664975540620786183594699522048","operator":1,"slotIndex":2,"timestamp":"1642074362","value":["10","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimSignatureR8x":"19151655656571068723188718866820691386512454028254006139907638885547326917694","issuerClaimSignatureR8y":"17463616698941210521990412259215791048145070157919873499989757246656774123070","issuerClaimSignatureS":"1268035173625987886471230795279546403676700496822588311134000495794122363162","issuerAuthClaim":["304427537360709784173770334266246861770","0","9582165609074695838007712438814613121302719752874385708394134542816240804696","18271435592817415588213874506882839610978320325722319742324814767882756910515","11203087622270641253","0","0","0"],"issuerAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtpAuxHi":"0","issuerAuthClaimNonRevMtpAuxHv":"0","issuerAuthClaimNonRevMtpNoAux":"1","issuerAuthClaimsTreeRoot":"18337129644116656308842422695567930755039142442806278977230099338026575870840","issuerAuthRevTreeRoot":"0","issuerAuthRootsTreeRoot":"0"}`

	require.JSONEq(t, expectedJSONInputs, string(bytesInputs))

}

func TestAtomicQuerySigV2Outputs_CircuitUnmarshal(t *testing.T) {
	userID, err := idFromIntStr("19224224881555258540966250468059781351205177043309252290095510834143232000")
	require.NoError(t, err)

	userStateInt, ok := new(big.Int).SetString(
		"7608718875990494885422326673876913565155307854054144181362485232187902102852", 10)
	require.True(t, ok)
	userState, err := merkletree.NewHashFromBigInt(userStateInt)
	require.NoError(t, err)

	schemaInt, ok := new(big.Int).SetString("210459579859058135404770043788028292398", 10)
	require.True(t, ok)
	schema := core.NewSchemaHashFromInt(schemaInt)

	issuerClaimNonRevStateInt, ok := new(big.Int).SetString("19221836623970007220538457599669851375427558847917606787084815224761802529201", 10)
	require.True(t, ok)
	issuerClaimNonRevState, err := merkletree.NewHashFromBigInt(issuerClaimNonRevStateInt)
	require.Nil(t, err)

	issuerAuthStateInt, ok := new(big.Int).SetString("11672667429383627660992648216772306271234451162443612055001584519010749218959", 10)
	require.True(t, ok)
	issuerAuthState, err := merkletree.NewHashFromBigInt(issuerAuthStateInt)
	require.Nil(t, err)

	issuerID, err := idFromIntStr("24839761684028550613296892625503994006188774664975540620786183594699522048")
	require.Nil(t, err)

	values := make([]*big.Int, 64)
	for i := 0; i < 64; i++ {
		values[i] = big.NewInt(0)
	}
	values[0].SetInt64(20000101)
	values[63].SetInt64(9999)

	timestamp := int64(1651850376)

	expectedOut := AtomicQuerySigPubSignals{
		UserID:                 userID,
		UserState:              userState,
		Challenge:              big.NewInt(84239),
		ClaimSchema:            schema,
		IssuerID:               issuerID,
		IssuerAuthState:        issuerAuthState,
		IssuerClaimNonRevState: issuerClaimNonRevState,
		SlotIndex:              2,
		Values:                 values,
		Operator:               EQ,
		Timestamp:              timestamp,
	}

	out := new(AtomicQuerySigPubSignals)
	err = out.PubSignalsUnmarshal([]byte(
		`["11672667429383627660992648216772306271234451162443612055001584519010749218959", "19224224881555258540966250468059781351205177043309252290095510834143232000", "7608718875990494885422326673876913565155307854054144181362485232187902102852", "84239", "24839761684028550613296892625503994006188774664975540620786183594699522048", "19221836623970007220538457599669851375427558847917606787084815224761802529201", "1651850376", "210459579859058135404770043788028292398", "2", "1", "20000101", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "9999"]`))
	require.NoError(t, err)
	require.Equal(t, expectedOut, *out)
}
