package circuits

import (
	"errors"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
	"math/big"
)

const (
	// AuthenticationVerificationKey is verification key to verify auth circuit
	AuthenticationVerificationKey VerificationKeyJSON = `{"protocol":"groth16","curve":"bn128","nPublic":3,"vk_alpha_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["21186122754510938844473484121803028805768823868659420429167031962104213452669","11531036153408267367981904689583322772277231048216817576309813840083888223526"],["10692495955024261993776637845359675478723917354154593765559727707373795521628","4488222557627980933779869049485361123419155363899313279650131295533574955936"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["14480256767620451318587913463852985291987730174383323706971686426192206586228","13794842641958534223890803477584411495136489019918046681255402493033902669593","1"],["15899669153041742461768612098706524993401689577923839624297665212120517575519","8416106942975678531708060814592791926993765111819924718825496398881896100576","1"],["21287922739003385816480150654484934434031086395597647322040273495223392444173","7860334010448425278721389847502162976670934187890845446945915828310145702769","1"],["11065398733589914616819940103547091917179463489998190517391929200753651172846","16010781869086024312453962077351326782445934594671040759005152350849483388443","1"]]}`

	// AuthenticationPublicSignalsSchema is schema to parse json data for additional information in auth circuit
	AuthenticationPublicSignalsSchema PublicSchemaJSON = `{"challenge":0,"userState":1,"userID":2}`
)

// AuthenticationLevels is number of levels currently used by authentication circuits
const AuthenticationLevels = 40

// AuthCircuit is circuit for basic authentication
type AuthCircuit struct {
	BaseCircuit
}

// nolint // common approach to register default supported circuit
func init() {
	RegisterCircuit(AuthCircuitID, &AuthCircuit{})
}

// GetVerificationKey returns key to verify proof
func (c *AuthCircuit) GetVerificationKey() VerificationKeyJSON {
	return AuthenticationVerificationKey
}

// GetPublicSignalsSchema returns schema to parse public inputs
func (c AuthCircuit) GetPublicSignalsSchema() PublicSchemaJSON {
	return AuthenticationPublicSignalsSchema
}

// PrepareInputs returns inputs for id state circuit as map
func (c *AuthCircuit) PrepareInputs(in TypedInputs) (map[string]interface{}, error) {

	authInputs, ok := in.(AuthInputs)
	if !ok {
		return nil, errors.New("wrong type of input arguments")
	}
	inputs := make(map[string]interface{})

	inputs["userID"] = authInputs.ID.BigInt().String()
	inputs["userState"] = authInputs.State.StateStr()

	inputs["userAuthClaim"] = bigIntArrayToStringArray(authInputs.AuthClaim.Slots)

	inputs["userAuthClaimMtp"] = bigIntArrayToStringArray(PrepareSiblings(authInputs.AuthClaim.Proof.Siblings, AuthenticationLevels))
	inputs["userAuthClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(authInputs.AuthClaimNonRevocationProof.Siblings, AuthenticationLevels))

	inputs["userClaimsTreeRoot"] = authInputs.State.ClaimsRootStr()
	inputs["userRevTreeRoot"] = authInputs.State.RevocationRootStr()
	inputs["userRootsTreeRoot"] = authInputs.State.RootOfRootsRootStr()

	inputs["challenge"] = authInputs.Challenge.String()
	inputs["challengeSignatureR8x"] = authInputs.Signature.R8.X.String()
	inputs["challengeSignatureR8y"] = authInputs.Signature.R8.Y.String()
	inputs["challengeSignatureS"] = authInputs.Signature.S.String()

	if authInputs.AuthClaimNonRevocationProof.NodeAux == nil {
		inputs["userAuthClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		inputs["userAuthClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		inputs["userAuthClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(1).String() // (yes it's isOld = 1)
	} else {
		inputs["userAuthClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(0).String() // (no it's isOld = 0)
		if authInputs.AuthClaimNonRevocationProof.NodeAux.HIndex == nil {
			inputs["userAuthClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["userAuthClaimNonRevMtpAuxHi"] = authInputs.AuthClaimNonRevocationProof.NodeAux.HIndex.BigInt().String()
		}
		if authInputs.AuthClaimNonRevocationProof.NodeAux.HValue == nil {
			inputs["userAuthClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["userAuthClaimNonRevMtpAuxHv"] = authInputs.AuthClaimNonRevocationProof.NodeAux.HValue.BigInt().String()
		}
	}

	return inputs, nil
}

// AuthInputs ZK inputs
type AuthInputs struct {
	ID *core.ID

	State TreeState

	AuthClaim                   Claim
	AuthClaimNonRevocationProof Proof

	Signature *babyjub.Signature
	Challenge *big.Int

	TypedInputs
}
