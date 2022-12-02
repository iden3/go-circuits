package testing

import (
	"context"
	"encoding/hex"
	"math/big"
	"testing"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
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

func AuthV2ClaimFromPubKey(X, Y *big.Int) (*core.Claim, error) {
	var schemaHash core.SchemaHash
	schemaEncodedBytes, _ := hex.DecodeString("013fd3f623559d850fb5b02ff012d0e2")
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

	state, _ := poseidon.Hash([]*big.Int{claimsTree.Root().BigInt(), big.NewInt(0), big.NewInt(0)})
	// create new identity
	identifier, err := core.IdGenesisFromIdenState(core.TypeDefault,
		state)
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

func GlobalTree(ctx context.Context) *merkletree.MerkleTree {
	// init global tree
	globalTree, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)
	if err != nil {
		panic(err)
	}
	return globalTree
}

type IdentityTest struct {
	ID        core.ID
	Clt       *merkletree.MerkleTree
	Ret       *merkletree.MerkleTree
	Rot       *merkletree.MerkleTree
	AuthClaim *core.Claim
	PK        *babyjub.PrivateKey
}

func NewIdentity(t testing.TB, privKHex string) *IdentityTest {

	it := IdentityTest{}
	var err error

	// init claims tree

	it.Clt, err = merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 32)
	if err != nil {
		t.Fatalf("Error creating Claims merkle tree: %v", err)
	}
	it.Ret, err = merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 32)
	if err != nil {
		t.Fatalf("Error creating Revocation merkle tree: %v", err)
	}
	it.Rot, err = merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 32)
	if err != nil {
		t.Fatalf("Error creating Roots merkle tree: %v", err)
	}

	// extract pubKey
	key, X, Y := ExtractPubXY(privKHex)
	it.PK = key

	// create auth claim
	authClaim, err := AuthV2ClaimFromPubKey(X, Y)
	if err != nil {
		t.Fatalf("Error creating auth claim: %v", err)
	}
	it.AuthClaim = authClaim

	// add auth claim to claimsMT
	hi, hv, err := authClaim.HiHv()
	if err != nil {
		t.Fatalf("Error getting auth claim hashes: %v", err)
	}

	err = it.Clt.Add(context.Background(), hi, hv)
	if err != nil {
		t.Fatalf("Error adding Auth claim to Claims merkle tree: %v", err)
	}

	state := it.State(t)

	identifier, err := IDFromState(state.BigInt())
	if err != nil {
		t.Fatalf("Error generating id from state: %v", err)
	}

	it.ID = *identifier

	return &it
}

func (it *IdentityTest) SignBBJJ(challenge []byte) (*babyjub.Signature, error) {
	// sign challenge
	return SignBBJJ(it.PK, challenge)
}

func (it *IdentityTest) State(t testing.TB) *merkletree.Hash {
	state, err := core.IdenState(it.Clt.Root().BigInt(), it.Ret.Root().BigInt(), it.Rot.Root().BigInt())
	if err != nil {
		t.Fatalf("Error generating state: %v", err)
	}
	hash, err := merkletree.NewHashFromBigInt(state)
	if err != nil {
		t.Fatalf("Error generating state hash: %v", err)
	}
	return hash
}

//func (it *IdentityTest) AuthMTPStrign(t testing.TB) (proof []string) {
//	p, _ := it.ClaimMTPRaw(t, it.AuthClaim)
//	return PrepareSiblingsStr(p.AllSiblings(), 32)
//}

func (it *IdentityTest) SignClaimBBJJ(claim *core.Claim) (*babyjub.Signature, error) {
	hashIndex, hashValue, err := claim.HiHv()
	if err != nil {
		return nil, err
	}

	commonHash, err := poseidon.Hash([]*big.Int{hashIndex, hashValue})
	if err != nil {
		return nil, err
	}

	return SignBBJJ(it.PK, commonHash.Bytes())

}

// ClaimMTPRaw returns the merkle proof of a claim
func (it *IdentityTest) ClaimMTPRaw(t testing.TB, claim *core.Claim) (proof *merkletree.Proof, value *big.Int) {
	hi, _, err := claim.HiHv()
	if err != nil {
		t.Fatalf("Error generating claim hash: %v", err)
	}

	proof, value, err = it.Clt.GenerateProof(context.Background(), hi, nil)
	if err != nil {
		t.Fatalf("Error generating claim proof: %v", err)
	}
	return proof, value
}

// ClaimMTP returns processed merkle proof
//func (it *IdentityTest) ClaimMTP(t testing.TB, claim *core.Claim) (sibling []string, nodeAux *NodeAuxValue) {
//	proof, _ := it.ClaimMTPRaw(t, claim)
//	sib, aux := PrepareProof(proof)
//	return sib, &aux
//}

func (it *IdentityTest) ClaimRevMTPRaw(t testing.TB, claim *core.Claim) (proof *merkletree.Proof, value *big.Int) {
	// add auth claim to claimsMT
	revNonce := claim.GetRevocationNonce()

	proof, value, err := it.Ret.GenerateProof(context.Background(), new(big.Int).SetUint64(revNonce), nil)
	if err != nil {
		t.Fatalf("Error generating claim proof: %v", err)
	}
	return proof, value
}

func (it *IdentityTest) ClaimRevMTP(claim *core.Claim) (sibling []string, nodeAux *NodeAuxValue, err error) {
	// add auth claim to claimsMT
	revNonce := claim.GetRevocationNonce()

	proof, _, err := it.Ret.GenerateProof(context.Background(), new(big.Int).SetUint64(revNonce), nil)
	if err != nil {
		return nil, nil, err
	}

	sib, aux := PrepareProof(proof)
	return sib, &aux, err

}

func (it *IdentityTest) AddClaim(t testing.TB, claim *core.Claim) {
	// add claim to claimsMT
	hi, hv, err := claim.HiHv()
	if err != nil {
		t.Fatal(err)
	}

	err = it.Clt.Add(context.Background(), hi, hv)
	if err != nil {
		t.Fatal(err)
	}

}

func (it *IdentityTest) SignClaim(t testing.TB, claim *core.Claim) *babyjub.Signature {
	hashIndex, hashValue, err := claim.HiHv()
	if err != nil {
		t.Fatalf("can't get hash index/value from claim %v", err)
	}

	commonHash, err := poseidon.Hash([]*big.Int{hashIndex, hashValue})
	if err != nil {
		t.Fatalf("can't hash index and value")
	}

	return it.PK.SignPoseidon(commonHash)
}
