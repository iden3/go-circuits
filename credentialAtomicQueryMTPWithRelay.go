package circuits

import (
	"errors"
	"math/big"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
)

const (
	// AtomicQueryMTPWithRelayPublicSignalsSchema is schema to parse json data for additional information
	AtomicQueryMTPWithRelayPublicSignalsSchema PublicSchemaJSON = `{"userID":0, "relayState":1,"challenge":2,"claimSchema":3,"slotIndex":4,"operator":5,"value":6,"timestamp":7, "issuerID":8}`

	// AtomicQueryMTPWithRelayVerificationKey is verification key to verify credentialAtomicQuery.circom
	AtomicQueryMTPWithRelayVerificationKey VerificationKeyJSON = `{"protocol":"groth16","curve":"bn128","nPublic":24,"vk_alpha_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["17739209144826664316056640844473811305321544482735557727503011902489994471005","10789664036755717987998621200038255054771986537051304436687329786487266634962"],["5062231752988175179293251301203850114096935004089418196383399922007660339534","10290805637292337716294987201015776444097863993655695451263313285335175163266"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["19899657351017624604829869442921475521242836560473389449892540308173846095143","16825324969163475046438822471418717274287872242224397051935733053299262571214","1"],["1766463950725205813209714805025282475107781091959936328963578569707248043719","13200352445084884027233932844652481064988863150067830041266065915436010007904","1"],["2005588141402690555997767233065240708994721733101686080577566537810711066835","1097538244704903934420075795952605052525786003139989695768549615313050571281","1"],["2000480008606634905564598433798362900337244374202912106628380114304079989960","11614875332338673831345650735611887260362047664795546491879119076567693204178","1"],["6403166290272022938877154151179952757081493536099833879356365196138983719241","1652146219150011496071997190385640253540297097853881364912094001087790134767","1"],["21256166921079393132686390006301590304861610373128661457721459746066148030928","1393046969358092361468389682806288549186732967237161681809059902024690752521","1"],["11207581261818900358501489145430787600119292804694112719038211698516221431354","4532056615074694572807190566254664253769626911071456283854615418401662306434","1"],["21658926409621929487099354777762881502225667616379271021696620559700507261289","6170388160449052649196510618049074709179225747360646605329037171596486222849","1"],["12341052619547168610575345748925844376333151064120114186413259458365779184909","15349175921243148365521897275852741213323399163966688806888956081426688543757","1"],["3763848052447409226711593169251055481534964898774158842392935701593027950684","10357254361424986365908098062315069489392406266160665486904678618942368948643","1"],["21218105791768500561487015859928460803593714275328130420977077395756195043078","6980042006995207711637038794975410275617761789689837830698149271502179749764","1"],["19025551694385847215822690946885065529745833635442139541197696470679450173604","7819476310999926498579867399859219017717635917936748227198270497671542123461","1"],["15556640716734185282512998009749473241995810860913872370960676482879328806352","20687803721982681863772947085726085100439597348504303310662910675388448962372","1"],["1496489559601623707143419489924918914626326257981064602718739614161863208599","9491711119719100834670434032930763534992455810407750803227856691181208058297","1"],["3879681323183149354609557109761073791594607184721237793962947637680399929875","3331701865161424321330691031455732260668458290709186518045507655782800474277","1"],["12017692481325014868163789972086855275690145960290500453631790369676661367323","6755625841907242609992188013659953520574633054062605115867870538245910413064","1"],["18860270261051222317719746117448693266349504182519108452844976805703246749507","7800108537464003272374297094926187062172489201720444937122868893468249966420","1"],["20195677302503501819375778530434444993357841818327605442277720890880628149672","2096127219987178215470568766504800107854095867917890657494007947321658891928","1"],["765137581081171971724525311659704164047891522125094112152473237784601125773","21305117960593610380177694721666722602200571173382282472556627949147946053382","1"],["20275720636296403706698757259824020979634512917218559776670538164586713765939","17757151498508809072375312203121776168455295880230954175994017361723537609758","1"],["3348248569466497622529285814223979250413064069497154357370437241187806594066","7005268095290136448256884044321134777219419342548762474787149465744150531412","1"],["14333981057690937365547039120068317632586461421344843650752514721783327205945","21732391104742760632879837429707205395429985371127989790123614777854630980933","1"],["18696905186151648958322137172903048613854623285373385644051352557472231687145","20775959668892609875569940800419680434153739541204239106195534645128848617308","1"],["14281813693248518015989867057186387695890054599976689397908270182322842792807","17482874663363250998278300327410272371317769223800423787615144787272359052325","1"],["10764607669824733251417767988073945908516757076067767044629085163503468876493","7169446875314675148921422243897278223691880339565592937557948456313319358634","1"]]}`
)

// LevelsAtomicQueryMTPWithRelayCircuit is number of merkle tree levels credentialAtomicQuery.circom compiled with
const LevelsAtomicQueryMTPWithRelayCircuit = 40

// ValueArraySizeAtomicQueryMTPWithRelayCircuit size of value array
const ValueArraySizeAtomicQueryMTPWithRelayCircuit = 16

type AtomicQueryMTPWithRelay struct{}

// AtomicQueryMTPWithRelayInputs represents input data for kyc and kycBySignatures circuits
type AtomicQueryMTPWithRelayInputs struct {
	// auth
	ID                 *core.ID
	AuthClaim          Claim
	AuthClaimRevStatus RevocationStatus
	Challenge          *big.Int
	Signature          *babyjub.Signature

	CurrentStateTree TreeState

	// relay
	UserStateInRelayClaim Claim

	// claim
	Claim
	RevocationStatus

	// query
	Query

	TypedInputs
}

// nolint // common approach to register default supported circuit
func init() {
	RegisterCircuit(AtomicQueryMTPWithRelayCircuitID, &AtomicQueryMTPWithRelay{})
}

func (c *AtomicQueryMTPWithRelay) PrepareInputs(in TypedInputs) (map[string]interface{}, error) {
	atomicInput, ok := in.(AtomicQueryMTPWithRelayInputs)
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

	relayInputs, err := c.prepareRelayClaimInputs(atomicInput.UserStateInRelayClaim)
	if err != nil {
		return nil, err
	}

	return mergeMaps(claimInputs, authClaimInputs, queryInputs, relayInputs), nil
}

// PrepareRegularClaimInputs prepares inputs for regular claims
func (c *AtomicQueryMTPWithRelay) prepareRegularClaimInputs(claim Claim, rs RevocationStatus) (map[string]interface{}, error) {

	inputs := map[string]interface{}{
		"issuerClaim": bigIntArrayToStringArray(claim.Slots),
		"issuerClaimMtp": bigIntArrayToStringArray(
			PrepareSiblings(claim.Proof.Siblings, LevelsAtomicQueryMTPWithRelayCircuit)),
		"issuerClaimClaimsTreeRoot": claim.TreeState.
			ClaimsRootStr(),
		"issuerClaimRevTreeRoot": claim.TreeState.
			RevocationRootStr(),
		"issuerClaimRootsTreeRoot": claim.TreeState.
			RootOfRootsRootStr(),
		"issuerClaimIdenState": claim.TreeState.StateStr(),
		"issuerID":             claim.IssuerID.BigInt().String(),
	}

	// revocation
	inputs["issuerClaimNonRevState"] = rs.TreeState.StateStr()
	inputs["issuerClaimNonRevRootsTreeRoot"] = rs.TreeState.
		RootOfRootsRootStr()
	inputs["issuerClaimNonRevRevTreeRoot"] = rs.TreeState.
		RevocationRootStr()
	inputs["issuerClaimNonRevClaimsTreeRoot"] = rs.TreeState.
		ClaimsRootStr()

	// claim non revocation

	inputs["issuerClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(rs.Proof.Siblings, LevelsAtomicQueryMTPWithRelayCircuit))

	if rs.Proof.NodeAux == nil {
		inputs["issuerClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		inputs["issuerClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		inputs["issuerClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(1).String() // (yes it's isOld = 1)
	} else {
		inputs["issuerClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(0).String() // (no it's isOld = 0)
		if rs.Proof.NodeAux.HIndex == nil {
			inputs["issuerClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["issuerClaimNonRevMtpAuxHi"] = rs.Proof.NodeAux.HIndex.BigInt().String()
		}
		if rs.Proof.NodeAux.HValue == nil {
			inputs["issuerClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["issuerClaimNonRevMtpAuxHv"] = rs.Proof.NodeAux.HValue.BigInt().String()
		}
	}

	inputs["claimSchema"] = new(big.Int).SetBytes(claim.Schema[:]).String()
	inputs["timestamp"] = new(big.Int).SetInt64(claim.CurrentTimeStamp).String()

	return inputs, nil
}

// PrepareAuthClaimInputs prepare inputs for authorization (ID ownership)
func (c *AtomicQueryMTPWithRelay) prepareAuthClaimInputs(in *AtomicQueryMTPWithRelayInputs) (map[string]interface{}, error) {

	if in.Signature == nil {
		return nil, errors.New("signature is null")
	}

	inputs := make(map[string]interface{})
	inputs["userID"] = in.ID.BigInt().String()
	inputs["challenge"] = in.Challenge.String()

	inputs["userAuthClaim"] = bigIntArrayToStringArray(in.AuthClaim.Slots)
	inputs["userAuthClaimMtp"] = bigIntArrayToStringArray(
		PrepareSiblings(in.AuthClaim.Proof.Siblings, LevelsAtomicQueryMTPWithRelayCircuit))

	// Note: we don't setup inputs user state, e.g. ["hoIdenState"] = in.CurrentStateTree.StateStr() here
	// as there is no need for it with relay
	inputs["userClaimsTreeRoot"] = in.CurrentStateTree.ClaimsRootStr()
	inputs["userRevTreeRoot"] = in.CurrentStateTree.RevocationRootStr()
	inputs["userRootsTreeRoot"] = in.CurrentStateTree.RootOfRootsRootStr()

	inputs["userAuthClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(in.AuthClaimRevStatus.Proof.Siblings, LevelsAtomicQueryMTPWithRelayCircuit))

	if in.AuthClaimRevStatus.Proof.NodeAux == nil {
		inputs["userAuthClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		inputs["userAuthClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		inputs["userAuthClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(1).String() // (yes it's isOld = 1)
	} else {
		inputs["userAuthClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(0).String() // (no it's isOld = 0)
		if in.AuthClaimRevStatus.Proof.NodeAux.HIndex == nil {
			inputs["userAuthClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["userAuthClaimNonRevMtpAuxHi"] = in.AuthClaimRevStatus.Proof.NodeAux.HIndex.BigInt().String()
		}
		if in.AuthClaimRevStatus.Proof.NodeAux.HValue == nil {
			inputs["userAuthClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["userAuthClaimNonRevMtpAuxHv"] = in.AuthClaimRevStatus.Proof.NodeAux.HValue.BigInt().String()
		}
	}

	inputs["challengeSignatureR8x"] = in.Signature.R8.X.String()
	inputs["challengeSignatureR8y"] = in.Signature.R8.Y.String()
	inputs["challengeSignatureS"] = in.Signature.S.String()

	return inputs, nil
}

func (c *AtomicQueryMTPWithRelay) prepareQueryInputs(in *AtomicQueryMTPWithRelayInputs) (map[string]interface{}, error) {
	inputs := make(map[string]interface{})
	inputs["slotIndex"] = in.Query.SlotIndex
	values, err := PrepareCircuitArrayValues(in.Query.Values, ValueArraySizeAtomicQueryMTPWithRelayCircuit)
	if err != nil {
		return nil, err
	}
	inputs["value"] = bigIntArrayToStringArray(values)
	inputs["operator"] = in.Query.Operator

	return inputs, nil
}

// Prepares inputs for the claim that user state is in relay state
func (c *AtomicQueryMTPWithRelay) prepareRelayClaimInputs(claim Claim) (map[string]interface{}, error) {
	inputs := map[string]interface{}{
		"relayState": claim.TreeState.StateStr(),
		"userStateInRelayClaimMtp": bigIntArrayToStringArray(
			PrepareSiblings(claim.Proof.Siblings, LevelsAtomicQueryMTPWithRelayCircuit)),
		"userStateInRelayClaim":         bigIntArrayToStringArray(claim.Slots),
		"relayProofValidClaimsTreeRoot": claim.TreeState.ClaimsRootStr(),
		"relayProofValidRevTreeRoot":    claim.TreeState.RevocationRootStr(),
		"relayProofValidRootsTreeRoot":  claim.TreeState.RootOfRootsRootStr(),
	}
	return inputs, nil
}

// GetVerificationKey returns verification key for circuit
func (c *AtomicQueryMTPWithRelay) GetVerificationKey() VerificationKeyJSON {
	return AtomicQueryMTPWithRelayVerificationKey
}

// GetPublicSignalsSchema returns schema to parse public inputs
func (c AtomicQueryMTPWithRelay) GetPublicSignalsSchema() PublicSchemaJSON {
	return AtomicQueryMTPWithRelayPublicSignalsSchema
}
