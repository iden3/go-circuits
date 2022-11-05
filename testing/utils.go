package testing

import (
	"encoding/hex"
	"io"
	"math/big"
	"os"
	"testing"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql/v2"
)

func TestData(t *testing.T, fileName string, data string, generate bool) string {
	t.Helper()
	path := "testdata/" + fileName + ".json"

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0755)
	defer f.Close()
	if err != nil {
		t.Fatalf("Error open a file %s: %s", path, err)
	}

	if generate {
		_, err := f.WriteString(data)
		if err != nil {
			t.Fatalf("Error writing to file %s: %s", path, err)
		}

		return data
	}

	fileBytes, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("Error read file %s: %s", path, err)
	}
	return string(fileBytes)
}

// SignPoseidon signs prepared data ( value in field Q)
func SignPoseidon(pk *babyjub.PrivateKey, data []byte) ([]byte, error) {

	if pk == nil {
		panic("pk is nil")
	}

	message := big.NewInt(0).SetBytes(data)

	signature := pk.SignPoseidon(message)

	compressed := signature.Compress()

	return compressed[:], nil
}

func SignBBJJ(key *babyjub.PrivateKey, sigInput []byte) (*babyjub.Signature, error) {
	signature, err := SignPoseidon(key, sigInput)
	if err != nil {
		return nil, err
	}

	var sig [64]byte
	copy(sig[:], signature)

	return new(babyjub.Signature).Decompress(sig)
}

type NodeAuxValue struct {
	Key   *merkletree.Hash
	Value *merkletree.Hash
	NoAux string
}

func getNodeAuxValue(p *merkletree.Proof) NodeAuxValue {

	// proof of inclusion
	if p.Existence {
		return NodeAuxValue{
			Key:   &merkletree.HashZero,
			Value: &merkletree.HashZero,
			NoAux: "0",
		}
	}

	// proof of non-inclusion (NodeAux exists)
	if p.NodeAux != nil && p.NodeAux.Value != nil && p.NodeAux.Key != nil {
		return NodeAuxValue{
			Key:   p.NodeAux.Key,
			Value: p.NodeAux.Value,
			NoAux: "0",
		}
	}
	// proof of non-inclusion (NodeAux does not exist)
	return NodeAuxValue{
		Key:   &merkletree.HashZero,
		Value: &merkletree.HashZero,
		NoAux: "1",
	}
}

func PrepareProof(proof *merkletree.Proof) ([]string, NodeAuxValue) {
	return PrepareSiblingsStr(proof.AllSiblings(), 32), getNodeAuxValue(proof)
}

func ExtractPubXY(privKHex string) (key *babyjub.PrivateKey, x, y *big.Int) {
	// Extract pubKey
	var k babyjub.PrivateKey
	if _, err := hex.Decode(k[:], []byte(privKHex)); err != nil {
		panic(err)
	}
	pk := k.Public()
	return &k, pk.X, pk.Y
}

func PrepareSiblingsStr(siblings []*merkletree.Hash, levels int) []string {
	// siblings := mtproof.AllSiblings()
	// Add the rest of empty levels to the siblings
	for i := len(siblings); i < levels; i++ {
		siblings = append(siblings, &merkletree.HashZero)
	}
	return HashToStr(siblings)
}

func HashToStr(siblings []*merkletree.Hash) []string {
	siblingsStr := make([]string, len(siblings))
	for i, sibling := range siblings {
		siblingsStr[i] = sibling.BigInt().String()
	}
	return siblingsStr
}

func IDFromState(state *big.Int) (*core.ID, error) {
	typ, err := core.BuildDIDType(core.DIDMethodIden3, core.NoChain, core.NoNetwork)
	if err != nil {
		return nil, err
	}
	// create new identity
	return core.IdGenesisFromIdenState(typ, state)
}
