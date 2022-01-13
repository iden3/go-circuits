package circuits

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestAuthCircuit_PrepareInputs(t *testing.T) {

	ctx := context.Background()
	privKeyHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	var privKey babyjub.PrivateKey
	if _, err := hex.Decode(privKey[:], []byte(privKeyHex)); err != nil {
		panic(err)
	}

	claim, err := AuthClaimFromPubKey(privKey.Public().X, privKey.Public().Y)
	assert.Nil(t, err)
	identifier, claimsTree, revTree, currentState, err := createAuthClaim(ctx, claim)
	assert.Nil(t, err)

	authEntry := claim.TreeEntry()
	hIndex, err := authEntry.HIndex()
	assert.Nil(t, err)

	proof, _, err := claimsTree.GenerateProof(ctx, hIndex.BigInt(), claimsTree.Root())
	assert.Nil(t, err)

	//MTP Claim not revoked
	revNonce := claim.GetRevocationNonce()
	revNonceInt := new(big.Int).SetUint64(revNonce)
	proofNotRevoke, _, err := revTree.GenerateProof(ctx, revNonceInt, revTree.Root())
	assert.Nil(t, err)

	challenge := big.NewInt(1)

	message := big.NewInt(0).SetBytes(challenge.Bytes())

	signature := privKey.SignPoseidon(message)

	c, err := GetCircuit(AuthCircuitID)
	assert.Nil(t, err)

	var nonRevProof Proof
	nonRevProof.Siblings = proofNotRevoke.AllSiblings()
	nonRevProof.NodeAux = nil

	if proofNotRevoke.NodeAux != nil {
		nonRevProof.NodeAux = &NodeAux{
			HIndex: proofNotRevoke.NodeAux.Key,
			HValue: proofNotRevoke.NodeAux.Key,
		}
	}

	var mtp Proof
	mtp.Siblings = proof.AllSiblings()
	mtp.NodeAux = nil

	if proof.NodeAux != nil {
		mtp.NodeAux = &NodeAux{
			HIndex: proof.NodeAux.Key,
			HValue: proof.NodeAux.Key,
		}
	}

	state := TreeState{
		State:          currentState,
		ClaimsRoot:     claimsTree.Root(),
		RevocationRoot: revTree.Root(),
		RootOfRoots:    &merkletree.HashZero,
	}

	inputs, err := c.PrepareInputs(AuthInputs{
		ID:    identifier,
		State: state,
		AuthClaim: Claim{
			Schema:           claim.GetSchemaHash(),
			Slots:            getSlots(claim),
			Proof:            mtp,
			TreeState:        state,
			CurrentTimeStamp: 0,
		},
		AuthClaimNonRevocationProof: nonRevProof,
		Signature:                   signature,
		Challenge:                   challenge.Int64(),
	})
	assert.Nil(t, err)
	fmt.Println(inputs)
	bytesInputs, err := json.Marshal(inputs)
	assert.Nil(t, err)

	expectedJSONInputs := `{"authClaim":["251025091000101825075425831481271126140","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"authClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtpAuxHi":"0","authClaimNonRevMtpAuxHv":"0","authClaimNonRevMtpNoAux":"1","challenge":"1","challengeSignatureR8x":"8553678144208642175027223770335048072652078621216414881653012537434846327449","challengeSignatureR8y":"5507837342589329113352496188906367161790372084365285966741761856353367255709","challengeSignatureS":"2093461910575977345603199789919760192811763972089699387324401771367839603655","claimsTreeRoot":"14501975351413460283779241106398661838785725538630637996477950952692691051377","id":"323416925264666217617288569742564703632850816035761084002720090377353297920","revTreeRoot":"0","rootsTreeRoot":"0","state":"18311560525383319719311394957064820091354976310599818797157189568621466950811"}`

	var actualInputs map[string]interface{}
	err = json.Unmarshal(bytesInputs, &actualInputs)
	assert.Nil(t, err)

	var expectedInputs map[string]interface{}
	err = json.Unmarshal([]byte(expectedJSONInputs), &expectedInputs)
	assert.Nil(t, err)

	assert.Equal(t, actualInputs, expectedInputs)

}

func createAuthClaim(
	ctx context.Context, authClaim *core.Claim) (
	*core.ID, *merkletree.MerkleTree, *merkletree.MerkleTree, *merkletree.Hash, error) {
	claimTreeStorage := memory.NewMemoryStorage()
	claimsTree, err := merkletree.NewMerkleTree(ctx, claimTreeStorage, 40)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	var identifier *core.ID

	entry := authClaim.TreeEntry()
	err = claimsTree.AddEntry(ctx, &entry)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	identifier, err = core.CalculateGenesisID(claimsTree.Root())
	if err != nil {
		return nil, nil, nil, nil, err
	}
	treeStorage := memory.NewMemoryStorage()
	revTree, err := merkletree.NewMerkleTree(ctx, treeStorage, 40)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	state, err := merkletree.HashElems(
		claimsTree.Root().BigInt(),
		revTree.Root().BigInt(),
		merkletree.HashZero.BigInt())
	return identifier, claimsTree, revTree, state, err
}
func AuthClaimFromPubKey(X, Y *big.Int) (*core.Claim, error) {
	var schemaHash core.SchemaHash
	schemaEncodedBytes, _ := hex.DecodeString("7c0844a075a9ddc7fcbdfb4f88acd9bc")
	copy(schemaHash[:], schemaEncodedBytes)

	// NOTE: We take nonce as hash of public key to make it random
	// We don't use random number here because this test vectors will be used for tests
	// and have randomization inside tests is usually a bad idea
	revNonce, err := poseidon.Hash([]*big.Int{X})
	if err != nil {
		return nil, err
	}
	return core.NewClaim(schemaHash,
		core.WithIndexDataInts(X, Y),
		core.WithRevocationNonce(revNonce.Uint64()))
}

func getSlots(claim *core.Claim) []*big.Int {
	inputs := make([]*big.Int, 0)

	entry := claim.TreeEntry()

	indexes := entry.Index()
	values := entry.Value()
	for _, index := range indexes {
		inputs = append(inputs, index.BigInt())
	}
	for _, value := range values {
		inputs = append(inputs, value.BigInt())
	}
	return inputs
}
