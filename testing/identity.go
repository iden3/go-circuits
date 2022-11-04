package testing

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/iden3/go-schema-processor/merklize"
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

func (it *IdentityTest) SignBBJJ(challenge []byte) (*babyjub.Signature, error) {
	// sign challenge
	return SignBBJJ(it.PK, challenge)
}

func (it *IdentityTest) State() (*merkletree.Hash, error) {
	state, err := core.IdenState(it.Clt.Root().BigInt(), it.Ret.Root().BigInt(), it.Rot.Root().BigInt())
	if err != nil {
		return nil, err
	}
	return merkletree.NewHashFromBigInt(state)
}

func (it *IdentityTest) AuthMTPStrign() (proof []string, err error) {
	p, _, err := it.ClaimMTPRaw(it.AuthClaim)
	return PrepareSiblingsStr(p.AllSiblings(), 32), err
}

func (it *IdentityTest) SignClaimBBJJ(claim *core.Claim) (*babyjub.Signature, error) {
	hashIndex, hashValue, err := claim.HiHv()
	if err != nil {
		return nil, err
	}

	commonHash, err := poseidon.Hash([]*big.Int{hashIndex, hashValue})
	if err != nil {
		return nil, err
	}

	sigBytes, err := Sign(it.PK, commonHash.Bytes())
	if err != nil {
		return nil, err
	}

	var sig [64]byte
	copy(sig[:], sigBytes)
	return new(babyjub.Signature).Decompress(sig)

}

func (it *IdentityTest) ClaimMTPRaw(claim *core.Claim) (proof *merkletree.Proof, value *big.Int, err error) {
	// add auth claim to claimsMT
	hi, _, err := claim.HiHv()
	if err != nil {
		return nil, nil, err
	}

	return it.Clt.GenerateProof(context.Background(), hi, nil)
}

func (it *IdentityTest) ClaimMTP(claim *core.Claim) (sibling []string, nodeAux *NodeAuxValue, err error) {
	// add auth claim to claimsMT
	hi, _, err := claim.HiHv()
	if err != nil {
		return nil, nil, err
	}

	proof, _, err := it.Clt.GenerateProof(context.Background(), hi, nil)
	if err != nil {
		return nil, nil, err
	}

	sib, aux := PrepareProof(proof)
	return sib, &aux, err
}

func (it *IdentityTest) ClaimRevMTPRaw(claim *core.Claim) (proof *merkletree.Proof, value *big.Int, err error) {
	// add auth claim to claimsMT
	revNonce := claim.GetRevocationNonce()

	return it.Ret.GenerateProof(context.Background(), new(big.Int).SetUint64(revNonce), nil)
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

func NewIdentity(privKHex string) (*IdentityTest, error) {

	it := IdentityTest{}
	var err error

	// init claims tree

	it.Clt, err = merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 4)
	if err != nil {
		return nil, err
	}
	it.Ret, err = merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 4)
	if err != nil {
		return nil, err
	}
	it.Rot, err = merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 4)
	if err != nil {
		return nil, err
	}

	// extract pubKey
	key, X, Y := ExtractPubXY(privKHex)
	it.PK = key

	// create auth claim
	authClaim, err := AuthClaimFromPubKey(X, Y)
	it.AuthClaim = authClaim

	// add auth claim to claimsMT
	hi, hv, err := authClaim.HiHv()

	err = it.Clt.Add(context.Background(), hi, hv)
	if err != nil {
		return nil, err
	}

	state, err := it.State()
	if err != nil {
		return nil, err
	}

	identifier, err := IDFromState(state.BigInt())
	if err != nil {
		return nil, err
	}

	it.ID = *identifier

	return &it, nil
}

func IDFromState(state *big.Int) (*core.ID, error) {
	typ, err := core.BuildDIDType(core.DIDMethodIden3, core.NoChain, core.NoNetwork)
	if err != nil {
		return nil, err
	}
	// create new identity
	return core.IdGenesisFromIdenState(typ, state)
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

func DefaultUserClaim(subject core.ID) (*core.Claim, error) {
	dataSlotA, _ := core.NewElemBytesFromInt(big.NewInt(10))
	nonce := 1
	var schemaHash core.SchemaHash
	schemaBytes, err := hex.DecodeString("ce6bb12c96bfd1544c02c289c6b4b987")
	if err != nil {
		return nil, err
	}
	copy(schemaHash[:], schemaBytes)

	return core.NewClaim(
		schemaHash,
		core.WithIndexID(subject),
		core.WithIndexData(dataSlotA, core.ElemBytes{}),
		core.WithExpirationDate(time.Unix(1669884010, 0)), //Thu Dec 01 2022 08:40:10 GMT+0000
		core.WithRevocationNonce(uint64(nonce)))

}

const TestClaimDocument = `{
   "@context": [
     "https://www.w3.org/2018/credentials/v1",
     "https://w3id.org/citizenship/v1",
     "https://w3id.org/security/bbs/v1"
   ],
   "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
   "type": ["VerifiableCredential", "PermanentResidentCard"],
   "issuer": "did:example:489398593",
   "identifier": 83627465,
   "name": "Permanent Resident Card",
   "description": "Government of Example Permanent Resident Card.",
   "issuanceDate": "2019-12-03T12:19:52Z",
   "expirationDate": "2029-12-03T12:19:52Z",
   "credentialSubject": {
     "id": "did:example:b34ca6cd37bbf23",
     "type": ["PermanentResident", "Person"],
     "givenName": "JOHN",
     "familyName": "SMITH",
     "gender": "Male",
     "image": "data:image/png;base64,iVBORw0KGgokJggg==",
     "residentSince": "2015-01-01",
     "lprCategory": "C09",
     "lprNumber": "999-999-999",
     "commuterClassification": "C1",
     "birthCountry": "Bahamas",
     "birthDate": "1958-07-17"
   }
 }`

func DefaultJSONUserClaim(subject core.ID) (*merklize.Merklizer, *core.Claim, error) {
	mz, err := merklize.MerklizeJSONLD(context.Background(), strings.NewReader(TestClaimDocument))
	if err != nil {
		return nil, nil, err
	}

	// issue issuerClaim for user
	dataSlotA, err := core.NewElemBytesFromInt(mz.Root().BigInt())

	fmt.Println("root", mz.Root().BigInt())

	var schemaHash core.SchemaHash
	schemaBytes, err := hex.DecodeString("ce6bb12c96bfd1544c02c289c6b4b987")
	copy(schemaHash[:], schemaBytes)

	nonce := 10

	claim, err := core.NewClaim(
		schemaHash,
		core.WithIndexID(subject),
		core.WithIndexData(dataSlotA, core.ElemBytes{}),
		core.WithExpirationDate(time.Unix(1669884010, 0)), //Thu Dec 01 2022 08:40:10 GMT+0000
		core.WithRevocationNonce(uint64(nonce)),
		core.WithFlagMerklize(core.MerklizePositionIndex))

	return mz, claim, err
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

func SignBBJJ(key *babyjub.PrivateKey, sigInput []byte) (*babyjub.Signature, error) {
	signature, err := Sign(key, sigInput)
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

// Sign signs prepared data ( value in field Q)
func Sign(pk *babyjub.PrivateKey, data []byte) ([]byte, error) {

	if pk == nil {
		panic("pk is nil")
	}

	message := big.NewInt(0).SetBytes(data)

	signature := pk.SignPoseidon(message)

	compressed := signature.Compress()

	return compressed[:], nil
}
