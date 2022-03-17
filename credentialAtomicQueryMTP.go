package circuits

import (
	"errors"
	"math/big"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
)

const (

	// AtomicQueryMTPPublicSignalsSchema is schema to parse json data for additional information
	AtomicQueryMTPPublicSignalsSchema PublicSchemaJSON = `{"user_identifier":0, "user_state":1,"challenge":2,"claimSchema":3, 
"claimIssuanceIdenState":4,"issuerID":5,"slotIndex":6,
"value_0": 7, "value_1": 8, "value_2": 9, "value_3": 10, "value_4": 11, "value_5": 12, "value_6": 13, "value_7": 14, 
"value_9": 15, "value_10": 16, "value_11": 17, "value_12": 18, "value_13": 19, "value_14": 20, "value_15": 21,
"operator":22,"timestamp":23}`

	// AtomicQueryMTPVerificationKey is verification key to verify credentialAtomicQuery.circom
	AtomicQueryMTPVerificationKey VerificationKeyJSON = `{"protocol": "groth16", "curve": "bn128", "nPublic": 25,"vk_alpha_1": ["20491192805390485299153009773594534940189261866228447918068658471970481763042", "9383485363053290200918347156157836566562967994039712273449902621266178545958", "1"], "vk_beta_2": [["6375614351688725206403948262868962793625744043794305715222011528459656738731", "4252822878758300859123897981450591353533073413197771768651442665752259397132"], ["10505242626370262277552901082094356697409835680220590971873171140371331206856", "21847035105528745403288232691147584728191162732299865338377159692350059136679"], ["1", "0"]], "vk_gamma_2": [["10857046999023057135944570762232829481370756359578518086990519993285655852781", "11559732032986387107991004021392285783925812861821192530917403151452391805634"], ["8495653923123431417604973247489272438418190587263600148770280649306958101930", "4082367875863433681332203403145435568316851327593401208105741076214120093531"], ["1", "0"]], "vk_delta_2": [["13107132117475003409171318602597442414973635462178052455107248605726824686786", "18678237349875993587284438467330802171064406089452957032787708614340302811776"], ["695498743144798772709427481062787722110252648261037964403246998468865370328", "10014740407522614120704386145939961794516151733688919687138580787896046933049"], ["1", "0"]], "vk_alphabeta_12": [[["2029413683389138792403550203267699914886160938906632433982220835551125967885", "21072700047562757817161031222997517981543347628379360635925549008442030252106"], ["5940354580057074848093997050200682056184807770593307860589430076672439820312", "12156638873931618554171829126792193045421052652279363021382169897324752428276"], ["7898200236362823042373859371574133993780991612861777490112507062703164551277", "7074218545237549455313236346927434013100842096812539264420499035217050630853"]], [["7077479683546002997211712695946002074877511277312570035766170199895071832130", "10093483419865920389913245021038182291233451549023025229112148274109565435465"], ["4595479056700221319381530156280926371456704509942304414423590385166031118820", "19831328484489333784475432780421641293929726139240675179672856274388269393268"], ["11934129596455521040620786944827826205713621633706285934057045369193958244500", "8037395052364110730298837004334506829870972346962140206007064471173334027475"]]], "IC": [["2249076505664092983852047605850201977366125504409718995142474948822915275124", "18610501877749909312661024840990750503923789269965735782253989223703641044204", "1"], ["19225357083747843745877287792187980458686178531470346294120613801669990385034", "18255159635797336474597124207808270208873472431111273568639225582762316233210", "1"], ["1872047666130099865518794749378356174634488444208521352527410894829039262562", "5501461194676288166103412209388614215739674091276674933768471937746543083155", "1"], ["2117253491981529522741306345850790976259450139154469941600464668730676490210", "14538229340058440946273494827246477710949073175789251321311186932208250056456", "1"], ["15097029929155871276093019263894222268456028662349292196226815256763173391183", "8530971376572538713035355718486350890113450204228119540772361046041767223001", "1"], ["16980632763351803998642704354973223446304284022465774270796312991413512311920", "6246310990403199228778272001740226995159531700876011276142912751517257695485", "1"], ["723624801996160335388082569566266775618299847707010536456463166404361010815", "1751971000048345196684616188912410900138898704226432889662325003690374927363", "1"], ["19083098587497983490677170771960526919648951080969749172755371490700135939286", "2446861806081191786196310001119439505235795489814484940830981343999254989053", "1"], ["319601282073248594170790171675495568748408297599523853378031308383960944484", "4418656910153262490545944935615866550024466711499397964432294841039990906019", "1"], ["20916098107097040216248562282502720585673566713220555735729454376704661076292", "20630583298338358030997649373806790965124691031976340176063813983521501172850", "1"], ["18414376764363893654964213616492271902255518796801229280999482786916726661297", "6752532411159525644897904253594430113407969857169924104699380936715696677044", "1"], ["4312364836353645416042081692851251137448793117962964178194636268117033978679", "15645700840385670977459813382187350606824808638834980339225241282440662180894", "1"], ["13495759601041831628192876429772641019063922239872429515790283801274006341306", "15666312713022380173317264226994868889842519315034284935236883899180531107425", "1"], ["1363394027939337998627110755702625412703424780264289413577607230882977374325", "2105026416919050684643130981211204060066962939303416476167981449170525368695", "1"], ["20897594563865864315070321790393647126427624780419629795122531264284407073875", "18275966091023840610191363235432577837318833188945081235598056223151545167495", "1"], ["9474734731755754734694018207248698346573006429744400256979442033205912406528", "15351670975085966749731852208689330900259360990049256160975590913944335799", "1"], ["4643302259780668805076208099553668563935992396718802860313067933881323525216", "8890592102940111864335941443691402024100765115121554253478288559694997303572", "1"], ["4231649475791627099467736232786096317710287950165249887143856434186700274873", "9817310077401181725755821316898399833841349847334052770376960675960662797286", "1"], ["18880302048781963966250287511911780691111756421387343085902596316199796578469", "9612970005445585470055683174386095337303208868284060871714243131226684071499", "1"], ["21782303734067336297703283409700310004335316303633467349897129616277211501224", "19205221564482243027284306826239915562928475604975110127243832111548984030484", "1"], ["6567312628950824554839440178786145714154768082202256650602092675589436300545", "12625417733183959013629913979719466639445829795612651433332739147705597698732", "1"], ["2750975951953665797530206896306738164469131566379392037758791392412760342900", "19823089972157690207893321422534525431135299159534580536074095317556786459302", "1"], ["11683374516331627901791998726987142117983454531551347954056209884363558930241", "11142327551447362982172105562486087625295663480070608998591162158688783138586", "1"], ["9849413879780831010429478833908928781415003566731748742213468146427824416817", "3901990769989183054553913758964312069810602757565595071395370601419730458903", "1"], ["5496251019573961109708232531272976500797837166658935408811341188383118001576", "20849556562477685543056321074593177652010192571121861406302446960950693894929", "1"], ["18099100904063705084074899054316881792422561463211285296738841275396641189930", "9210196641156816195917839441462781206991012653794289877792246294543967776194", "1"]]}`
)

// LevelsAtomicQueryMTPCircuit is number of merkle tree levels credentialAtomicQuery.circom compiled with
const LevelsAtomicQueryMTPCircuit = 40

// ValueArraySizeAtomicQueryMTPCircuit size of value array
const ValueArraySizeAtomicQueryMTPCircuit = 16

// AtomicQueryMTP represents credentialAtomicQuery.circom
type AtomicQueryMTP struct{}

// AtomicQueryMTPInputs represents input data for kyc and kycBySignatures circuits
type AtomicQueryMTPInputs struct {
	// auth
	ID                 *core.ID
	AuthClaim          Claim
	AuthClaimRevStatus RevocationStatus
	Challenge          *big.Int
	Signature          *babyjub.Signature

	CurrentStateTree TreeState

	// claim
	Claim
	RevocationStatus

	// query
	Query

	TypedInputs
}

// nolint // common approach to register default supported circuit
func init() {
	RegisterCircuit(AtomicQueryMTPCircuitID, &AtomicQueryMTP{})
}

// PrepareInputs returns inputs as a map for credentialAtomicQuery.circom
func (c *AtomicQueryMTP) PrepareInputs(in TypedInputs) (map[string]interface{}, error) {

	atomicInput, ok := in.(AtomicQueryMTPInputs)
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
func (c *AtomicQueryMTP) prepareRegularClaimInputs(claim Claim, rs RevocationStatus) (map[string]interface{}, error) {

	inputs := map[string]interface{}{
		"claim": bigIntArrayToStringArray(claim.Slots),
		"claimIssuanceMtp": bigIntArrayToStringArray(
			PrepareSiblings(claim.Proof.Siblings, LevelsAtomicQueryMTPCircuit)),
		"claimIssuanceClaimsTreeRoot": claim.TreeState.
			ClaimsRootStr(),
		"claimIssuanceRevTreeRoot": claim.TreeState.
			RevocationRootStr(),
		"claimIssuanceRootsTreeRoot": claim.TreeState.
			RootOfRootsRootStr(),
		"claimIssuanceIdenState": claim.TreeState.StateStr(),
		"issuerID":               claim.IssuerID.BigInt().String(),
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

	inputs["claimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(rs.Proof.Siblings, LevelsAtomicQueryMTPCircuit))

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
func (c *AtomicQueryMTP) prepareAuthClaimInputs(in *AtomicQueryMTPInputs) (map[string]interface{}, error) {

	if in.Signature == nil {
		return nil, errors.New("signature is null")
	}

	inputs := make(map[string]interface{})
	inputs["id"] = in.ID.BigInt().String()
	inputs["challenge"] = in.Challenge.String()

	inputs["authClaim"] = bigIntArrayToStringArray(in.AuthClaim.Slots)
	inputs["authClaimMtp"] = bigIntArrayToStringArray(
		PrepareSiblings(in.AuthClaim.Proof.Siblings, LevelsAtomicQueryMTPCircuit))

	inputs["hoIdenState"] = in.CurrentStateTree.StateStr()
	inputs["hoClaimsTreeRoot"] = in.CurrentStateTree.ClaimsRootStr()
	inputs["hoRevTreeRoot"] = in.CurrentStateTree.RevocationRootStr()
	inputs["hoRootsTreeRoot"] = in.CurrentStateTree.RootOfRootsRootStr()

	inputs["authClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(in.AuthClaimRevStatus.Proof.Siblings, LevelsAtomicQueryMTPCircuit))

	if in.AuthClaimRevStatus.Proof.NodeAux == nil {
		inputs["authClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		inputs["authClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		inputs["authClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(1).String() // (yes it's isOld = 1)
	} else {
		inputs["authClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(0).String() // (no it's isOld = 0)
		if in.AuthClaimRevStatus.Proof.NodeAux.HIndex == nil {
			inputs["authClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["authClaimNonRevMtpAuxHi"] = in.AuthClaimRevStatus.Proof.NodeAux.HIndex.BigInt().String()
		}
		if in.AuthClaimRevStatus.Proof.NodeAux.HValue == nil {
			inputs["authClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["authClaimNonRevMtpAuxHv"] = in.AuthClaimRevStatus.Proof.NodeAux.HValue.BigInt().String()
		}
	}

	inputs["challengeSignatureR8x"] = in.Signature.R8.X.String()
	inputs["challengeSignatureR8y"] = in.Signature.R8.Y.String()
	inputs["challengeSignatureS"] = in.Signature.S.String()

	return inputs, nil
}

func (c *AtomicQueryMTP) prepareQueryInputs(in *AtomicQueryMTPInputs) (map[string]interface{}, error) {
	inputs := make(map[string]interface{})
	inputs["slotIndex"] = in.Query.SlotIndex
	values, err := PrepareCircuitArrayValues(in.Query.Values, ValueArraySizeAtomicQueryMTPCircuit)
	if err != nil {
		return nil, err
	}
	inputs["value"] = bigIntArrayToStringArray(values)
	inputs["operator"] = in.Query.Operator

	return inputs, nil
}

// GetVerificationKey returns verification key for circuit
func (c *AtomicQueryMTP) GetVerificationKey() VerificationKeyJSON {
	return AtomicQueryMTPVerificationKey
}

// GetPublicSignalsSchema returns schema to parse public inputs
func (c AtomicQueryMTP) GetPublicSignalsSchema() PublicSchemaJSON {
	return AtomicQueryMTPPublicSignalsSchema
}
