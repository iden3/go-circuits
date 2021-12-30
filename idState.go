package circuits

import (
	"errors"
	"math/big"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
)

const (
	// IDStateVerificationKey is verification key to verify auth circuit
	IDStateVerificationKey VerificationKeyJSON = `{"protocol":"groth16","curve":"bn128","nPublic":3,"vk_alpha_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["17243819072705542974859239394019464312409517831760771541411161923415836129282","20626180733016164852543146896316391121631414974857324436628093679771603687231"],["765928425270874872662096943454802784961955251042371420707998847506189795373","19009824542154438406993229783530927237993919239236852200068054752009586240055"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["21146318436711026540288376866714597128906872373301625984874947621447116062545","14396051576005909624826308405950201245300608934746748059285893688415423173432","1"],["3991931362647581814082427408587332172186848280823923818872875656222025914096","587367118372840728385877169558621073833853321542253821100289123891573264123","1"],["11858028750740588278962130809484684328126502557706050129106158404382227234276","79886190397361450684330170982792732981160727224641252475703568532050904401","1"],["12279541336611168039304680364302879110516557139382004453057502950376720247004","3378344441800334805146493177924925098568695987941738981092194276026305937459","1"]]}`

	// IDStatePublicSignalsSchema is schema to parse json data for additional information in auth circuit
	IDStatePublicSignalsSchema PublicSchemaJSON = `{"id":0,"oldIdState":1,"newIdState":2}`
)

// IDStateLevels is number of levels currently used by idState circuits
const IDStateLevels = 4

// IDStateCircuit represents idState circuit
type IDStateCircuit struct {
}

// nolint // common approach to register default supported circuit
func init() {
	RegisterCircuit(IDStateCircuitID, &IDStateCircuit{})
}

// PrepareInputs returns inputs for id state circuit as map
func (c *IDStateCircuit) PrepareInputs(in TypedInputs) (map[string]interface{}, error) {

	ownerShipInputs, ok := in.(IDOwnershipGenesisInputs)
	if !ok {
		return nil, errors.New("wrong type of input arguments")
	}
	inputs := make(map[string]interface{})
	inputs["id"] = ownerShipInputs.ID.BigInt().String()
	inputs["oldIdState"] = ownerShipInputs.OldTreeState.State.BigInt().String()
	inputs["newIdState"] = ownerShipInputs.NewState.BigInt().String()

	inputs["authClaimMtp"] = bigIntArrayToStringArray(
		PrepareSiblings(ownerShipInputs.AuthClaim.Proof.Siblings, IDStateLevels))
	inputs["authClaim"] = bigIntArrayToStringArray(ownerShipInputs.AuthClaim.Slots)

	inputs["signatureR8x"] = ownerShipInputs.Signature.R8.X.String()
	inputs["signatureR8y"] = ownerShipInputs.Signature.R8.Y.String()
	inputs["signatureS"] = ownerShipInputs.Signature.S.String()

	inputs["claimsTreeRoot"] = ownerShipInputs.OldTreeState.ClaimsRootStr()
	inputs["revTreeRoot"] = ownerShipInputs.OldTreeState.RevocationRootStr()
	inputs["rootsTreeRoot"] = ownerShipInputs.OldTreeState.RootOfRootsRootStr()

	err := handleAuthMTPInputs(ownerShipInputs.AuthClaimNonRevocationProof, inputs)
	if err != nil {
		return nil, err
	}

	return inputs, nil
}

func handleAuthMTPInputs(mtp Proof, inputs map[string]interface{}) (err error) {

	inputs["authClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(mtp.Siblings, IDStateLevels))

	if mtp.NodeAux == nil {
		inputs["authClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		inputs["authClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		inputs["authClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(1).String() // (yes it's isOld = 1) // TODO: clarify with Jordi
		return nil
	}
	inputs["authClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(0).String() // (no it's isOld = 0)
	if mtp.NodeAux.HIndex == nil {
		inputs["authClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
	} else {
		inputs["authClaimNonRevMtpAuxHi"] = mtp.NodeAux.HIndex.BigInt().String()
	}
	if mtp.NodeAux.HValue == nil {
		inputs["authClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
	} else {
		inputs["authClaimNonRevMtpAuxHv"] = mtp.NodeAux.HValue.BigInt().String()
	}

	return nil
}

// GetVerificationKey returns key to verify proof
func (c *IDStateCircuit) GetVerificationKey() VerificationKeyJSON {
	return IDStateVerificationKey
}

// GetPublicSignalsSchema returns schema to parse public inputs
func (c *IDStateCircuit) GetPublicSignalsSchema() PublicSchemaJSON {
	return IDStatePublicSignalsSchema
}

// IDOwnershipGenesisInputs ZK inputs
type IDOwnershipGenesisInputs struct {
	ID *core.ID

	OldTreeState TreeState
	NewState     *merkletree.Hash

	AuthClaim                   Claim
	AuthClaimNonRevocationProof Proof
	Signature                   *babyjub.Signature

	TypedInputs
}
