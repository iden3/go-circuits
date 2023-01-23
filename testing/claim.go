package testing

import (
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	core "github.com/iden3/go-iden3-core"
)

func DefaultUserClaim(t testing.TB, subject core.ID) *core.Claim {
	dataSlotA, _ := core.NewElemBytesFromInt(big.NewInt(10))
	nonce := 1
	var schemaHash core.SchemaHash
	schemaBytes, err := hex.DecodeString("ce6bb12c96bfd1544c02c289c6b4b987")
	if err != nil {
		t.Fatal(err)
	}
	copy(schemaHash[:], schemaBytes)

	claim, err := core.NewClaim(
		schemaHash,
		core.WithIndexID(subject),
		core.WithIndexData(dataSlotA, core.ElemBytes{}),
		core.WithExpirationDate(time.Unix(1669884010, 0)), //Thu Dec 01 2022 08:40:10 GMT+0000
		core.WithRevocationNonce(uint64(nonce)))
	if err != nil {
		t.Fatal(err)
	}

	return claim

}

func UserStateCommitmentClaim(t testing.TB, secret *big.Int) *core.Claim {
	dataSlotA, err := core.NewElemBytesFromInt(secret)
	if err != nil {
		t.Fatalf("failed get NewElemBytesFromInt %v", err)
	}

	nonce := 145645
	var schemaHash core.SchemaHash
	schemaBytes, err := hex.DecodeString("da5b2efc8386250550e458a33b7926c5")
	if err != nil {
		t.Fatalf("failed decode schema hash %v", err)
	}
	copy(schemaHash[:], schemaBytes)

	claim, err := core.NewClaim(
		schemaHash,
		core.WithValueData(dataSlotA, core.ElemBytes{}),
		core.WithRevocationNonce(uint64(nonce)))
	if err != nil {
		t.Fatalf("failed create new claim %v", err)
	}

	return claim
}
