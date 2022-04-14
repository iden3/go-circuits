package identity

import (
	"context"
	"encoding/hex"
	"math/big"

	"github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
)

func AuthClaimFromPubKey(X, Y *big.Int) (*core.Claim, error) {
	var schemaHash core.SchemaHash
	schemaEncodedBytes, _ := hex.DecodeString("ca938857241db9451ea329256b9c06e5")
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

func Generate(ctx context.Context, privKHex string) (*core.ID,
	*merkletree.MerkleTree, *merkletree.MerkleTree, *merkletree.MerkleTree,
	error, *core.Claim, *babyjub.PrivateKey) {

	// extract pubKey
	var privKey babyjub.PrivateKey

	if _, err := hex.Decode(privKey[:], []byte(privKHex)); err != nil {
		panic(err)
	}
	X := privKey.Public().X
	Y := privKey.Public().Y

	// init claims tree
	claimsTree, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(),
		40)
	if err != nil {
		return nil, nil, nil, nil, err, nil, nil
	}
	// create auth claim
	authClaim, err := AuthClaimFromPubKey(X, Y)
	if err != nil {
		return nil, nil, nil, nil, err, nil, nil
	}

	// add auth claim to claimsMT
	hi, hv, err := claimsIndexValueHashes(*authClaim)
	if err != nil {
		return nil, nil, nil, nil, err, nil, nil
	}

	err = claimsTree.Add(ctx, hi, hv)
	if err != nil {
		return nil, nil, nil, nil, err, nil, nil
	}

	// create new identity
	identifier, err := core.IdGenesisFromIdenState(core.TypeDefault, claimsTree.Root().BigInt())
	if err != nil {
		return nil, nil, nil, nil, err, nil, nil
	}

	revTree, _ := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 40)
	rootsTree, _ := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 40)

	return identifier, claimsTree, revTree, rootsTree, nil, authClaim, &privKey
}

func CalcStateFromRoots(claimsTree *merkletree.MerkleTree,
	optTrees ...*merkletree.MerkleTree) (*merkletree.Hash, error) {
	revTreeRoot := merkletree.HashZero.BigInt()
	rootsTreeRoot := merkletree.HashZero.BigInt()
	if len(optTrees) > 0 {
		revTreeRoot = optTrees[0].Root().BigInt()
	}
	if len(optTrees) > 1 {
		rootsTreeRoot = optTrees[1].Root().BigInt()
	}
	state, err := merkletree.HashElems(
		claimsTree.Root().BigInt(),
		revTreeRoot,
		rootsTreeRoot)
	return state, err
}

/*
This method is to generate auth claim, identity, all its trees, state
and sign a challenge with the claim private key.
*/
func AuthClaimFullInfo(ctx context.Context, privKeyHex string,
	challenge *big.Int) (*core.ID, *core.Claim, *merkletree.Hash,
	*merkletree.MerkleTree,
	*merkletree.MerkleTree, *merkletree.MerkleTree, *merkletree.Proof,
	*merkletree.Proof, *babyjub.Signature, error) {

	identity, claimsTree, revTree, rootsTree, err, claim, privateKey :=
		Generate(ctx, privKeyHex)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, err
	}

	//Proof claim exists
	hi, _, err := claimsIndexValueHashes(*claim)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, err
	}
	claimEntryMTP, _, _ := claimsTree.GenerateProof(ctx, hi, claimsTree.Root())

	//Proof claim not revoked
	revNonce := claim.GetRevocationNonce()
	revNonceInt := new(big.Int).SetUint64(revNonce)
	claimNonRevMTP, _, _ := revTree.GenerateProof(ctx, revNonceInt,
		revTree.Root())

	//Calculate state
	state, _ := CalcStateFromRoots(claimsTree, revTree, rootsTree)

	//Calculate signature
	message := big.NewInt(0).SetBytes(challenge.Bytes())
	challengeSignature := privateKey.SignPoseidon(message)

	return identity, claim, state, claimsTree, revTree, rootsTree, claimEntryMTP, claimNonRevMTP, challengeSignature, nil
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

// coreElemBytesFromHashPtr coverts *merkletree.Hash to core.ElemBytes
func coreElemBytesFromHashPtr(h *merkletree.Hash) core.ElemBytes {
	var eb core.ElemBytes
	copy(eb[:], h[:])
	return eb
}
