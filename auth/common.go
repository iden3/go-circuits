package auth

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
	"math/big"
)

func InitStateWithClaim(
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
	fmt.Println(claimsTree.Root().String())
	fmt.Println(identifier)
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

func ClaimFromPubKey(X, Y *big.Int) (*core.Claim, error) {
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
