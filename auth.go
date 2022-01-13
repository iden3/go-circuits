package circuits

import (
	"errors"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
	"math/big"
	"strconv"
)

const (
	// AuthenticationVerificationKey is verification key to verify auth circuit
	AuthenticationVerificationKey VerificationKeyJSON = `{"protocol":"groth16","curve":"bn128","nPublic":3,"vk_alfa_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["1427945781425577300804801797571114274701932698324508247041613394101830311827","13443075556866321726995222645953898133295278871291405063161198336509258498458"],["942405004580446723014888105701908316913295753168759573857038748164305486094","13640936337424071512073923505871606551736185071795349227911060116070299254651"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["3222906315520974555079899857198161806154736423978266716098130738474773565251","12864572401271513883192718950116158255918717201899581326172321570117179787039","1"],["13954287744602042247963990482729987438210821095088440992269303092560304225832","5137362606811979107510299725357204386117487156330804918868951420267055894731","1"],["6771039716794620184161972545357461521717348339582105645118747678533230901289","13883467378973205387964830785862722648703775331051536586988653947906683648728","1"],["16327560345481823995400991783644653517793528773256685891999434719410002917057","13517878251828423758914772813218047195632584751031888244542378238477652224121","1"]]}`

	// AuthenticationPublicSignalsSchema is schema to parse json data for additional information in auth circuit
	AuthenticationPublicSignalsSchema PublicSchemaJSON = `{"user_identifier":0,"challenge":1}`
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

	inputs["id"] = authInputs.ID.BigInt().String()
	inputs["state"] = authInputs.State.StateStr()

	inputs["authClaim"] = bigIntArrayToStringArray(authInputs.AuthClaim.Slots)

	inputs["authClaimMtp"] = bigIntArrayToStringArray(PrepareSiblings(authInputs.AuthClaim.Proof.Siblings, AuthenticationLevels))
	inputs["authClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(authInputs.AuthClaimNonRevocationProof.Siblings, AuthenticationLevels))

	inputs["claimsTreeRoot"] = authInputs.State.ClaimsRootStr()
	inputs["revTreeRoot"] = authInputs.State.RevocationRootStr()
	inputs["rootsTreeRoot"] = authInputs.State.RootOfRootsRootStr()

	inputs["challenge"] = strconv.FormatInt(authInputs.Challenge, 10)
	inputs["challengeSignatureR8x"] = authInputs.Signature.R8.X.String()
	inputs["challengeSignatureR8y"] = authInputs.Signature.R8.Y.String()
	inputs["challengeSignatureS"] = authInputs.Signature.S.String()

	if authInputs.AuthClaimNonRevocationProof.NodeAux == nil {
		inputs["authClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		inputs["authClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		inputs["authClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(1).String() // (yes it's isOld = 1)
	} else {
		inputs["authClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(0).String() // (no it's isOld = 0)
		if authInputs.AuthClaimNonRevocationProof.NodeAux.HIndex == nil {
			inputs["authClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["authClaimNonRevMtpAuxHi"] = authInputs.AuthClaimNonRevocationProof.NodeAux.HIndex.BigInt().String()
		}
		if authInputs.AuthClaimNonRevocationProof.NodeAux.HValue == nil {
			inputs["authClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["authClaimNonRevMtpAuxHv"] = authInputs.AuthClaimNonRevocationProof.NodeAux.HValue.BigInt().String()
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
	Challenge int64

	TypedInputs
}
