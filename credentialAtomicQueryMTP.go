package circuits

import (
	"errors"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
	"math/big"
)

const (

	// AtomicQueryMTPPublicSignalsSchema is schema to parse json data for additional information
	AtomicQueryMTPPublicSignalsSchema PublicSchemaJSON = `{"user_identifier":0, "hoIdenState":1,"challenge":2,"claimSchema":3,"slotIndex":4,"operator":5,"value":6,"timestamp":7}`

	// AtomicQueryMTPVerificationKey is verification key to verify credentialAtomicQuery.circom
	AtomicQueryMTPVerificationKey VerificationKeyJSON = `{"protocol":"groth16","curve":"bn128","nPublic":24,"vk_alfa_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["8345966871347009681987580398241979951082005320974694297632911455537869922674","3845962443574199519512824919128096336702083529573861267458127723213870242820"],["19285609556266370188038407272603672376532371354560635982657101523112830530481","17839206491247340630599275499216727237292668694348933025176123195671399945797"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["2249076505664092983852047605850201977366125504409718995142474948822915275124","18610501877749909312661024840990750503923789269965735782253989223703641044204","1"],["19225357083747843745877287792187980458686178531470346294120613801669990385034","18255159635797336474597124207808270208873472431111273568639225582762316233210","1"],["1872047666130099865518794749378356174634488444208521352527410894829039262562","5501461194676288166103412209388614215739674091276674933768471937746543083155","1"],["2117253491981529522741306345850790976259450139154469941600464668730676490210","14538229340058440946273494827246477710949073175789251321311186932208250056456","1"],["15097029929155871276093019263894222268456028662349292196226815256763173391183","8530971376572538713035355718486350890113450204228119540772361046041767223001","1"],["809498859591606931647767338518852079482624652223826092607972579151363552556","7916993785477663096926216707865311585854153882629434981137691759299692365434","1"],["2789744368752727816448927849961676923681987923293536583516666818765286064393","8826314455392257308756254977998572372849778267943868460406006287621946205998","1"],["13751787354066178237423830548900282739697965433107087240480775762231161375394","12447385631994792634896753491280065581918190714926012763077478300201874919515","1"],["18194123662869259073625778448062654458640616431340768676262481864654898113808","15145810125187381240273134008860826403885268178127779073439507483683756048239","1"],["7392044921514518909247315680613581630256136668171240440031758620072009093202","16046415290358875265844024268337556628709790992224448175569351019266900773608","1"],["4129655932932409786408218186729021017169476110638591228108218985534554436089","1354200906918755488165853308515200313893688935893243546762702622557015544368","1"],["7106941762885049302390672204965985870055101944019581612203611146555283385552","17017893749537353706057875645822167558098977164441388323202656831985800382082","1"],["12472172171700831587533337400352542019607957888994185084367540395042371016168","16355554737664845375155704544407745287819204443807958453977394723804641793537","1"],["11531012692973689000865081640442129515085283848024312369554243083102064612802","20185968271634230943148126998272037795765523744029068703636974772789206967757","1"],["3313326007867622950393750633963234542851634845425202218713910206845811946446","8018867751569529036245574991872735890918629590068368522539940575264484747587","1"],["16813489007488260763910363876405379921865763357171059059466380249257706535100","1651582772597323141148556593517782385167614641137472340618863887157115753990","1"],["9807098855365316353131155656986792069267525224395034599058886935820805494237","15668624605543894920660129234184036227464819292745520411526184734705184948861","1"],["1128342045213210192501027111552612413875085431291856084848194736370168315366","11697740356866902325039098063024961834179585421898986692515058954937120015064","1"],["3729408397528692012923021963789567153123987439055094654629997552490026818030","4350950166397486377460166038398777474404898530047455575552108795853345833741","1"],["20833653186208358546122347780297401332535758879349117219961223817867647287088","6903551349741869921978071726866220246360129424731548556337457450352889464855","1"],["9124277796826150535377204443550400511974222830728743840606347819804460878740","183859589323918711932148353480568930047989241670686650830670049727448835670","1"],["5292064874364109060451462120291729947197326606200973386984298873260495011210","6645319623953387718321419455556396372882041690187972074226862320881284878402","1"],["20460575293620302573930578307434114466331105216585658312662424724742533989407","11994867297304751517847726543466109007403426407914963205210143988458334958995","1"],["14488999583397351201513745279655051105175902716638126169366807273755368434778","17822278767617968361857975763250570334066964662863703995684297235985701884261","1"],["2787631692449660523511401951092699049135669028532736371213247869891070100657","15893580551377297832521859578619130603216193721769126889242403823303470332705","1"]]}`
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
