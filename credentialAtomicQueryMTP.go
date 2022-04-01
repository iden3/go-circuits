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
	AtomicQueryMTPPublicSignalsSchema PublicSchemaJSON = `{"user_identifier":0, "user_state":1,"challenge":2,"issuerClaimSchema":3, 
"issuerClaimIdenState":4,"issuerID":5,"slotIndex":6,
"value_0": 7, "value_1": 8, "value_2": 9, "value_3": 10, "value_4": 11, "value_5": 12, "value_6": 13, "value_7": 14, 
"value_9": 15, "value_10": 16, "value_11": 17, "value_12": 18, "value_13": 19, "value_14": 20, "value_15": 21,
"operator":22,"timestamp":23}`

	// AtomicQueryMTPVerificationKey is verification key to verify credentialAtomicQuery.circom
	AtomicQueryMTPVerificationKey VerificationKeyJSON = `{"protocol":"groth16","curve":"bn128","nPublic":25,"vk_alpha_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["2516317384470477005677933398394575672754559385922262000599044671448065360143","16859622147443472181845080888624282759103852400344400046208649108117512951862"],["5554790419103019736758978401677687187888347248274265142709185612247663975517","16616548149501504746923066581983999266936143892418507535685180405929938448251"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["10209119751974272026802861695941000641181805749262912563258537296235084800697","9693538468624752478092494894393489982498011835144967632834424789938483198734","1"],["3511266824882574806332450290147886385092779581021484757010353573885976434054","18606536905470685002367197906557999286439672519722550542577741968102792880715","1"],["27341717499390527575317306248630680358261131297716153676798176844769558757","18207903514320711422679216954214479735653125553680331479668354595305182324489","1"],["5577607678939291070884062108198915621363266095458597345262191226329134903716","2453496842662487533803598591290806366818829568142649575129891147145244714571","1"],["18513589765478033590228306202179633195855431125126377696000837588536679075699","8043783355099396884030234836320495621251258307997827491468205667379601228848","1"],["798947675949019899260525549367506167298216494658797066367914560035068592155","14426274908497180912697663418731102829377865529825130524234015299993120777134","1"],["6429235961477386192381518291708673292727068348686761860205826442824033985184","16083017783244004804522843132842722708975214615203044852826077244476847782114","1"],["16591766035064756743160455828423364363183812887742653616579357777717974660895","15886486100434791428108648227017909629043031660842698127756093617254618291281","1"],["12910151212913555614553175644457253063998623131739213050611591092299132490841","846425573896321645565768359959768951010986912550793115758113686910752748716","1"],["1912932587066415983946484463677129438398979161798099986475290394456049862772","8236113219829639414355620429437203102270656211332864252865980373548506242250","1"],["7190314349386213377241874963541888573190002149562157920574648103729768274885","20255035912492100151730277472662478980963032832117784228200091899375729569461","1"],["4284232798846544967337598011893961404329309173416573572998495823935789994727","15762686004172187316484543418397072562890620529535646780181824651794601724929","1"],["3796628351075444915813482199733118234574607573281493453114559798990427655834","13149082409076033985557441730264671796614345907007394669399243352898431017217","1"],["18504377172047442067485350186672883883177644457359229406203607345241171171383","21612483792768493409465869383194381299301360567512340189089757161062649608947","1"],["11351792963490652653061645107277880526436597956809271383220021885820210009586","21159323202508975159016192650745500877564679086616593581947279603682137080908","1"],["4443908562279196975412927301934026627218123764220844892035005302618963458564","2966928321106903348452126057495706714664744840041999526475890800999691529229","1"],["12396729799303081048511069827137886571956311655907012724700947918318556079328","5126417782456421318946572501737839176313033942572590957397084248294870265765","1"],["3211071359488262143482114487245008920240380583228595393962692827759081537128","594783618905105518960013938778133572404784268438443040295674732877156215844","1"],["3003228228132092140894668350331471603633108819597082465328199649773172728417","8094902572880206506585131564807726393809245128887014006428078088026690759052","1"],["12752328100377304826839927356182835411584710437611369610768017545610739913637","4870959533025478237353485096140666091219835531128430364467696556669522451364","1"],["14743166125281678242296590332603676267914571152070998643989741645190133517161","12428469644007367665788163192314719571635335713181737179939841362666839171035","1"],["15697973560601505135237628287877858252665480822163316474457601344440862006265","21117488656936455231300527226228449420225401107007338144697618917792083935254","1"],["18079264048175722959515172577260287077482072055227404561873429504697970289869","8188656810775391648685991843417496839534269485145388478840285802350881419063","1"],["5129369021026351754804362997992516379409480079393753573170367448287316630976","10087594162701541396208174530630969603837185966332283691381781081670799410908","1"],["10620454384023403471888332548347415139310480697028067397918201008189933888419","123771019447375744038441611603067231444928915098261916310330827041380957676","1"],["15786541411191832347165520635390917405534111565831003915667764452792979750469","5861327436226369394564811190924226879843273074286812399096763717998967856077","1"]]}`
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

	// issuerClaim
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
func (c *AtomicQueryMTP) prepareRegularClaimInputs(issuerClaim Claim, rs RevocationStatus) (map[string]interface{}, error) {

	inputs := map[string]interface{}{
		"issuerClaim": bigIntArrayToStringArray(issuerClaim.Slots),
		"issuerClaimMtp": bigIntArrayToStringArray(
			PrepareSiblings(issuerClaim.Proof.Siblings, LevelsAtomicQueryMTPCircuit)),
		"issuerClaimClaimsTreeRoot": issuerClaim.TreeState.
			ClaimsRootStr(),
		"issuerClaimRevTreeRoot": issuerClaim.TreeState.
			RevocationRootStr(),
		"issuerClaimRootsTreeRoot": issuerClaim.TreeState.
			RootOfRootsRootStr(),
		"issuerClaimIdenState": issuerClaim.TreeState.StateStr(),
		"issuerID":             issuerClaim.IssuerID.BigInt().String(),
	}

	// revocation
	inputs["issuerClaimNonRevState"] = rs.TreeState.StateStr()
	inputs["issuerClaimNonRevRootsTreeRoot"] = rs.TreeState.
		RootOfRootsRootStr()
	inputs["issuerClaimNonRevRevTreeRoot"] = rs.TreeState.
		RevocationRootStr()
	inputs["issuerClaimNonRevClaimsTreeRoot"] = rs.TreeState.
		ClaimsRootStr()

	// issuerClaim non revocation

	inputs["issuerClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(rs.Proof.Siblings, LevelsAtomicQueryMTPCircuit))

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

	inputs["issuerClaimSchema"] = new(big.Int).SetBytes(issuerClaim.Schema[:]).String()
	inputs["timestamp"] = new(big.Int).SetInt64(issuerClaim.CurrentTimeStamp).String()

	return inputs, nil
}

// PrepareAuthClaimInputs prepare inputs for authorization (ID ownership)
func (c *AtomicQueryMTP) prepareAuthClaimInputs(in *AtomicQueryMTPInputs) (map[string]interface{}, error) {

	if in.Signature == nil {
		return nil, errors.New("signature is null")
	}

	inputs := make(map[string]interface{})
	inputs["userID"] = in.ID.BigInt().String()
	inputs["challenge"] = in.Challenge.String()

	inputs["userAuthClaim"] = bigIntArrayToStringArray(in.AuthClaim.Slots)
	inputs["userAuthClaimMtp"] = bigIntArrayToStringArray(
		PrepareSiblings(in.AuthClaim.Proof.Siblings, LevelsAtomicQueryMTPCircuit))

	inputs["userState"] = in.CurrentStateTree.StateStr()
	inputs["userClaimsTreeRoot"] = in.CurrentStateTree.ClaimsRootStr()
	inputs["userRevTreeRoot"] = in.CurrentStateTree.RevocationRootStr()
	inputs["userRootsTreeRoot"] = in.CurrentStateTree.RootOfRootsRootStr()

	inputs["userAuthClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(in.AuthClaimRevStatus.Proof.Siblings, LevelsAtomicQueryMTPCircuit))

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
