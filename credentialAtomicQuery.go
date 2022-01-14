package circuits

import (
	"errors"
	"math/big"
	"strconv"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
)

const (

	// AtomicQueryPublicSignalsSchema is schema to parse json data for additional information
	AtomicQueryPublicSignalsSchema PublicSchemaJSON = `{"challenge":0,"user_identifier":1,"hoIdenState":2,"claimSchema":3,"slotIndex":4,"operator":5,"value":6,"timestamp":7}`

	// AtomicQueryVerificationKey is verification key to verify credentialAtomicQuery.circom
	AtomicQueryVerificationKey VerificationKeyJSON = `{"protocol":"groth16","curve":"bn128","nPublic":8,"vk_alfa_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["1169491263441249022097370867498605029797936974767314436015661709565085840813","6337941376418541892612728636270479727016549855211404141815113972851604698054"],["17495580965920305552487152742784386501285635981179235266984962730654532618966","3863391113873496441976048896066137207399719893656311401891338682552227202390"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["19709737333033468828227684945302918740598103694820980384159902161079791811436","4944462845260797596862465592237553542763073512137597823278049758463885838730","1"],["1919325256450692423836436783216397955614161310216280261340525691136245416448","7688487314931461304466329067191350168577882595959740844510981800764540156137","1"],["10100361422720520193796310694197101888684164516574720788133205104335941354777","12986911456651289680505124769214732200195193750609629659493856018799998445248","1"],["8954637716564104807298057852397702093344458742754655656079826297423226917293","10477551600603018807254977969197771646220126097764592475933953639301828004581","1"],["4600868160045332613963627096387378474270103942893292757591031274353522762698","1615258613693893594835034364476450208042592018694912178707040419625965941807","1"],["13403587094673251526958093567855174864441491660275022552413449342284594006053","5456003665957341471178343812835752539050288289947056465960191530239607963272","1"],["13673795199410321359329148268354216879505247909324907829212794115410611057606","12630257678634354873891678406131165453286725478825317727136838727336866975676","1"],["21738527296093062372507791867431609055635933106974138638544850668897067561249","3198270437846861134674353018450883983418306003079912928031620268505406655718","1"],["15118182267429928078510798177085053204089797489052140355678667003871132105395","11146999716635173623394204092173216495853584938729645671265542159114747878420","1"]]}`
)

// LevelsAtomicQueryCircuit is number of merkle tree levels credentialAtomicQuery.circom compiled with
const LevelsAtomicQueryCircuit = 40

// AtomicQuery represents credentialAtomicQuery.circom
type AtomicQuery struct{}

// nolint // common approach to register default supported circuit
func init() {
	RegisterCircuit(AtomicQueryCircuitID, &AtomicQuery{})
}

// PrepareInputs returns inputs as a map for credentialAtomicQuery.circom
func (c *AtomicQuery) PrepareInputs(in TypedInputs) (map[string]interface{}, error) {

	atomicInput, ok := in.(AtomicQueryInputs)
	if !ok {
		return nil, errors.New("wrong type of input arguments %T")
	}

	claimInputs, err := c.prepareRegularClaimInputs(atomicInput.Claim, atomicInput.RevocationStatus)
	if err != nil {
		return nil, err
	}

	authClaimInputs, err := c.prepareAuthClaimInputs(&atomicInput)
	if err != nil {
		return nil, err
	}

	queryInputs, err := c.prepareQueryInputs(&atomicInput)
	if err != nil {
		return nil, err
	}

	return mergeMaps(claimInputs, authClaimInputs, queryInputs), nil
}

// PrepareRegularClaimInputs prepares inputs for regular claims
func (c *AtomicQuery) prepareRegularClaimInputs(claim Claim, rs RevocationStatus) (map[string]interface{}, error) {

	inputs := map[string]interface{}{
		"claim": bigIntArrayToStringArray(claim.Slots),
		"claimIssuanceMtp": bigIntArrayToStringArray(
			PrepareSiblings(claim.Proof.Siblings, LevelsAtomicQueryCircuit)),
		"claimIssuanceClaimsTreeRoot": claim.TreeState.
			ClaimsRootStr(),
		"claimIssuanceRevTreeRoot": claim.TreeState.
			RevocationRootStr(),
		"claimIssuanceRootsTreeRoot": claim.TreeState.
			RootOfRootsRootStr(),
		"claimIssuanceIdenState": claim.TreeState.StateStr(),
	}

	// revocation
	inputs["claimNonRevIssuerState"] = rs.TreeState.StateStr()
	inputs["claimNonRevIssuerRootsTreeRoot"] = rs.TreeState.
		RootOfRootsRootStr()
	inputs["claimNonRevIssuerRevTreeRoot"] = rs.TreeState.
		RevocationRootStr()
	inputs["claimNonRevIssuerClaimsTreeRoot"] = rs.TreeState.
		ClaimsRootStr()

	// claim non revocation

	inputs["claimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(rs.Proof.Siblings, LevelsAtomicQueryCircuit))

	if rs.Proof.NodeAux == nil {
		inputs["claimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		inputs["claimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		inputs["claimNonRevMtpNoAux"] = new(big.Int).SetInt64(1).String() // (yes it's isOld = 1)
	} else {
		inputs["claimNonRevMtpNoAux"] = new(big.Int).SetInt64(0).String() // (no it's isOld = 0)
		if rs.Proof.NodeAux.HIndex == nil {
			inputs["claimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["claimNonRevMtpAuxHi"] = rs.Proof.NodeAux.HIndex.BigInt().String()
		}
		if rs.Proof.NodeAux.HValue == nil {
			inputs["claimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["claimNonRevMtpAuxHv"] = rs.Proof.NodeAux.HValue.BigInt().String()
		}
	}

	inputs["claimSchema"] = new(big.Int).SetBytes(claim.Schema[:]).String()
	inputs["timestamp"] = new(big.Int).SetInt64(claim.CurrentTimeStamp).String()

	return inputs, nil
}

// PrepareAuthClaimInputs prepare inputs for authorization (ID ownership)
func (c *AtomicQuery) prepareAuthClaimInputs(in *AtomicQueryInputs) (map[string]interface{}, error) {

	if in.Signature == nil {
		return nil, errors.New("signature is null")
	}

	inputs := make(map[string]interface{})
	inputs["id"] = in.ID.BigInt().String()
	inputs["challenge"] = strconv.FormatInt(in.Challenge, 10)

	inputs["authClaim"] = bigIntArrayToStringArray(in.AuthClaim.Slots)
	inputs["authClaimMtp"] = bigIntArrayToStringArray(
		PrepareSiblings(in.AuthClaim.Proof.Siblings, LevelsAtomicQueryCircuit))

	inputs["hoIdenState"] = in.CurrentStateTree.StateStr()
	inputs["hoClaimsTreeRoot"] = in.CurrentStateTree.ClaimsRootStr()
	inputs["hoRevTreeRoot"] = in.CurrentStateTree.RevocationRootStr()
	inputs["hoRootsTreeRoot"] = in.CurrentStateTree.RootOfRootsRootStr()

	inputs["authClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(in.AuthClaim.Proof.Siblings, LevelsAtomicQueryCircuit))

	if in.AuthClaim.Proof.NodeAux == nil {
		inputs["authClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		inputs["authClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		inputs["authClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(1).String() // (yes it's isOld = 1)
	} else {
		inputs["authClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(0).String() // (no it's isOld = 0)
		if in.AuthClaim.Proof.NodeAux.HIndex == nil {
			inputs["authClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["authClaimNonRevMtpAuxHi"] = in.AuthClaim.Proof.NodeAux.HIndex.BigInt().String()
		}
		if in.AuthClaim.Proof.NodeAux.HValue == nil {
			inputs["authClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["authClaimNonRevMtpAuxHv"] = in.AuthClaim.Proof.NodeAux.HValue.BigInt().String()
		}
	}

	inputs["challengeSignatureR8x"] = in.Signature.R8.X.String()
	inputs["challengeSignatureR8y"] = in.Signature.R8.Y.String()
	inputs["challengeSignatureS"] = in.Signature.S.String()

	return inputs, nil
}

func (c *AtomicQuery) prepareQueryInputs(in *AtomicQueryInputs) (map[string]interface{}, error) {
	inputs := make(map[string]interface{})
	inputs["slotIndex"] = in.Query.SlotIndex
	inputs["value"] = in.Query.Value.String()
	inputs["operator"] = in.Query.Operator

	return inputs, nil
}

// AtomicQueryInputs represents input data for kyc and kycBySignatures circuits
type AtomicQueryInputs struct {
	// auth
	ID        *core.ID
	AuthClaim Claim
	Challenge int64
	Signature *babyjub.Signature

	CurrentStateTree TreeState

	// claim
	Claim
	RevocationStatus

	// query
	Query

	TypedInputs
}

// GetVerificationKey returns verification key for circuit
func (c *AtomicQuery) GetVerificationKey() VerificationKeyJSON {
	return AtomicQueryVerificationKey
}

// GetPublicSignalsSchema returns schema to parse public inputs
func (c AtomicQuery) GetPublicSignalsSchema() PublicSchemaJSON {
	return AtomicQueryPublicSignalsSchema
}
