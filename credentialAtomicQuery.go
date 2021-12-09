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
	AtomicQueryPublicSignalsSchema PublicSchemaJSON = `{"challenge":0,"id":1,"claimSchema":2,"slotIndex":3,"operator":4,"value":5,"timestamp":6,"queryOut":7}`

	// AtomicQueryVerificationKey is verification key to verify credentialAtomicQuery.circom
	AtomicQueryVerificationKey VerificationKeyJSON = `{"protocol": "groth16", "curve": "bn128", "nPublic": 8, "vk_alfa_1": ["20491192805390485299153009773594534940189261866228447918068658471970481763042", "9383485363053290200918347156157836566562967994039712273449902621266178545958", "1"], "vk_beta_2": [["6375614351688725206403948262868962793625744043794305715222011528459656738731", "4252822878758300859123897981450591353533073413197771768651442665752259397132"], ["10505242626370262277552901082094356697409835680220590971873171140371331206856", "21847035105528745403288232691147584728191162732299865338377159692350059136679"], ["1", "0"]], "vk_gamma_2": [["10857046999023057135944570762232829481370756359578518086990519993285655852781", "11559732032986387107991004021392285783925812861821192530917403151452391805634"], ["8495653923123431417604973247489272438418190587263600148770280649306958101930", "4082367875863433681332203403145435568316851327593401208105741076214120093531"], ["1", "0"]], "vk_delta_2": [["6658798542797909995864781879944799040899537016172171831790932785149453610055", "1562298809146080968827577809908963852565115288023590024163814284991401144898"], ["3191825062183459277939359172596315408477966175703846294889555106962624241398", "20519339564189899176468119116646833727193447453492900940798905509327633779887"], ["1", "0"]], "vk_alphabeta_12": [[["2029413683389138792403550203267699914886160938906632433982220835551125967885", "21072700047562757817161031222997517981543347628379360635925549008442030252106"], ["5940354580057074848093997050200682056184807770593307860589430076672439820312", "12156638873931618554171829126792193045421052652279363021382169897324752428276"], ["7898200236362823042373859371574133993780991612861777490112507062703164551277", "7074218545237549455313236346927434013100842096812539264420499035217050630853"]], [["7077479683546002997211712695946002074877511277312570035766170199895071832130", "10093483419865920389913245021038182291233451549023025229112148274109565435465"], ["4595479056700221319381530156280926371456704509942304414423590385166031118820", "19831328484489333784475432780421641293929726139240675179672856274388269393268"], ["11934129596455521040620786944827826205713621633706285934057045369193958244500", "8037395052364110730298837004334506829870972346962140206007064471173334027475"]]], "IC": [["13023325234621726744991201818852904343246754726627321756971569809461761301510", "4627042041328147677748594612884503303190747111559130457807863822879356686394", "1"], ["21701009070920454284358073721904882665075610556661162698776316509586680293539", "21661150983893193657270333686702824114081281721839686275999690856042977416297", "1"], ["21787583271867051626200152635616028738905703704066850965875203719896712092525", "19918413694472090495757399845118930730726873109192677620248610050704186803864", "1"], ["12277858583188038973997914869591833670418551799701699300383691103382685958368", "18214953439507947578028542581756241758945899029209951733459290841045637041148", "1"], ["19664052933043141234551924522147842438412587411585984757151148205591450337178", "720298257510679882876793881129676446455134521451364528108999698502197881664", "1"], ["18688453390521696716279099799801933696745094084039098289711918929961909837320", "20952565918901760033074795648475979781770363899601504201985288375230058015632", "1"], ["14560949225701877450724527157836529076276893765195935196598376415987249134191", "986681258442660196405130855868344283267504085773110067401219448660004061892", "1"], ["16469597978550750016028793487599799638561886653284000297911962182587936673854", "18948833696116823554497558267522852164303352403450263271235566859845671880571", "1"], ["326429509831569628631725783519163626129484691241912216909669104543411599420", "10464927334468254897017492641590561735374414531934221178214695442506060996408", "1"]]}`
)

// LevelsAtomicQueryCircuit is number of merkle tree levels credentialAtomicQuery.circom compiled with
const LevelsAtomicQueryCircuit = 40

// AtomicQuery represents credentialAtomicQuery.circom
type AtomicQuery struct{}

// nolint // common approach to register default supported circuit
func init() {
	RegisterCircuit(AtomicQueryID, &AtomicQuery{})
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
		"claim": bigIntArrayToStringArray(claim.ZKInputs),
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

	inputs["ClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(rs.Proof.Siblings, LevelsKYCCircuits))

	if rs.Proof.NodeAux == nil {
		inputs["claimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		inputs["claimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		inputs["claimNonRevMtpNoAux"] = new(big.Int).SetInt64(1).String() // (yes it's isOld = 1) // TODO: clarify with Jordi
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

	inputs["claimSchema"] = new(big.Int).SetBytes(claim.Schema[:])
	inputs["timestamp"] = new(big.Int).SetInt64(claim.CurrentTimeStamp)

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
	inputs["BBJClaimMtp"] = bigIntArrayToStringArray(
		PrepareSiblings(in.AuthClaim.Proof.Siblings, IDStateLevels))
	inputs["BBJClaimClaimsTreeRoot"] = in.AuthClaim.TreeState.ClaimsRoot.BigInt().String()
	inputs["BBJAx"] = in.AuthClaim.ZKInputs[2].String()
	inputs["BBJAy"] = in.AuthClaim.ZKInputs[3].String()
	inputs["challengeSignatureR8x"] = in.Signature.R8.X.String()
	inputs["challengeSignatureR8y"] = in.Signature.R8.Y.String()
	inputs["challengeSignatureS"] = in.Signature.S.String()

	inputs["BBJClaimRevTreeRoot"] = in.AuthClaim.TreeState.RevocationRootStr()
	inputs["BBJClaimRootsTreeRoot"] = in.AuthClaim.TreeState.RootOfRootsRootStr()

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

	// claim
	Claim
	RevocationStatus

	// query
	Query

	TypedInputs
}

// Query
type Query struct {
	SlotIndex int
	Value     *big.Int
	Operator  int
}

// GetVerificationKey returns verification key for circuit
func (c *AtomicQuery) GetVerificationKey() VerificationKeyJSON {
	return AtomicQueryVerificationKey
}

// GetPublicSignalsSchema returns schema to parse public inputs
func (c AtomicQuery) GetPublicSignalsSchema() PublicSchemaJSON {
	return AtomicQueryPublicSignalsSchema
}
