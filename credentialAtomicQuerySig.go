package circuits

import (
	"errors"
	"math/big"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
)

const (

	// AtomicQuerySigPublicSignalsSchema is schema to parse json data for additional information
	AtomicQuerySigPublicSignalsSchema PublicSchemaJSON = `{"user_identifier": 0, "user_state": 1, "challenge": 2, 
"claimSchema": 3, "issuerID": 4,"issuerIdenState":5, "slotIndex":6, "value_0": 7, "value_1": 8, "value_2": 9, 
"value_3": 10, "value_4": 11, "value_5": 12, "value_6": 13, "value_7": 14, "value_9": 15, "value_10": 16, 
"value_11": 17, "value_12": 18, "value_13": 19, "value_14": 20, "value_15": 21, "operator": 22, "timestamp": 23}`

	// AtomicQuerySigVerificationKey is verification key to verify credentialAttrQuerySig.circom
	AtomicQuerySigVerificationKey VerificationKeyJSON = `{"protocol": "groth16", "curve": "bn128", "nPublic": 25,"vk_alpha_1": ["20491192805390485299153009773594534940189261866228447918068658471970481763042", "9383485363053290200918347156157836566562967994039712273449902621266178545958", "1"], "vk_beta_2": [["6375614351688725206403948262868962793625744043794305715222011528459656738731", "4252822878758300859123897981450591353533073413197771768651442665752259397132"], ["10505242626370262277552901082094356697409835680220590971873171140371331206856", "21847035105528745403288232691147584728191162732299865338377159692350059136679"], ["1", "0"]], "vk_gamma_2": [["10857046999023057135944570762232829481370756359578518086990519993285655852781", "11559732032986387107991004021392285783925812861821192530917403151452391805634"], ["8495653923123431417604973247489272438418190587263600148770280649306958101930", "4082367875863433681332203403145435568316851327593401208105741076214120093531"], ["1", "0"]], "vk_delta_2": [["16600533772833073142844322890122270472057658183331179535525145485543448385110", "18244778749587621142126086471696940373711144948513833374855054051759852691684"], ["4215962030736476784972538490785643275546003802114602427601205846984024107422", "9110558419748582013666791324277443439732505195396662406524950769564563964845"], ["1", "0"]], "vk_alphabeta_12": [[["2029413683389138792403550203267699914886160938906632433982220835551125967885", "21072700047562757817161031222997517981543347628379360635925549008442030252106"], ["5940354580057074848093997050200682056184807770593307860589430076672439820312", "12156638873931618554171829126792193045421052652279363021382169897324752428276"], ["7898200236362823042373859371574133993780991612861777490112507062703164551277", "7074218545237549455313236346927434013100842096812539264420499035217050630853"]], [["7077479683546002997211712695946002074877511277312570035766170199895071832130", "10093483419865920389913245021038182291233451549023025229112148274109565435465"], ["4595479056700221319381530156280926371456704509942304414423590385166031118820", "19831328484489333784475432780421641293929726139240675179672856274388269393268"], ["11934129596455521040620786944827826205713621633706285934057045369193958244500", "8037395052364110730298837004334506829870972346962140206007064471173334027475"]]], "IC": [["9056879998269897110371040375505468838982983209796685277007510305400075177012", "19789845017300106440126278764635460044955090504006316759160341950439026845656", "1"], ["18565047771903659153084970115443706304427092001735932895479987211775691221799", "1890380070267698819780933683916218825658694779865483245184857637737925572517", "1"], ["780174388378650871177855968865080905147010409957331853547992473136475925082", "19345076338787764261593414865124630011860468307275361219728075189085316906779", "1"], ["5839453759380448434084840785397386469252292876551596693377773260707643997677", "19191052974828499829227258402089894454509644208712778416359150904826198484017", "1"], ["6930446571407405004115992447277808044605054218705389307783402643458912458491", "5237719106611425934344022276838267715438070999560740067171375974201442873442", "1"], ["18828755602729931743996744736808797329881222056309939372559568480401278441674", "20495364727031551730553719956843279309071839313920241802317821058111083742834", "1"], ["2177289760405971479304326230573129239605156904194731036196866879089736755117", "8309436281143662563471167008593299850722375072209871700247208979748184785020", "1"], ["1822713756099181151861797620014832340111711932397953019613326673166383382597", "17350467462357183650573216782623420080141850105956517700592016497416762224297", "1"], ["4182173256842953802678393992568903004008953726549159453108892294658950820637", "5015932771577006347090510477404246645932191810043904790816477644534678351741", "1"], ["10322763285220495535698837573603566028425070036218158529955648986731184293099", "15191393165341766925831748018063384873395961284917098355314187415162182983425", "1"], ["14635540627455317116767266115408095778004305055396737038328664715718995911097", "6274476450910807392421467671586715708128283235293299480879459953416127463591", "1"], ["19471189639284120858885769555502571241386062933933579451678221371379374108467", "3057589916365128829363168214165270067818068223837820321671641264293422105066", "1"], ["3325753276139723244687776223181920763062220238132224618230954557378439867077", "20370081391263589600073251015642162613324474510746328408692253226327388910953", "1"], ["18863379613583491352195174395201299623413804780835080867198276888826589265397", "220044460308574532255770615230779564226169768466073073775422221644645031485", "1"], ["8986641074262445224512405414286696325725021535802597736589870739879911602703", "10811714174032552513530341989176542537154690495259113570054090449862672856149", "1"], ["13111431078023507163445252924546463396507357949546468884500276614756245900955", "17198150567358837024653473900935897479920555279580743857945580687459546468326", "1"], ["452512845450091782297056664633480408234075293846952303968591065153277445893", "6929342087554203733415051265636038405601340653577554087304289561548617613819", "1"], ["21381572770361254827400653280346313817102017539058419350596474202913291246933", "5466626878558427070506660667678157238029907503593128659918464074764657358994", "1"], ["7057099376175917164763634189853067202294794878581143971584082318226124072287", "19218006258374634182917183627698971921964197695177296486228497489894956026832", "1"], ["18582444533258536336041116009976249164685351797917411708550087595414147574351", "11174282514445901032990345141996128548697041451923648995228598321191208552278", "1"], ["2038927065696494470008493874645348645975428252174564771046089581306633230478", "8887530817761518218638762438645644110292906593306870545133993801349431622094", "1"], ["10832793248883679183868393454688983335526485483542671882740369594446191504644", "5915387579363379113344452837140942803673388837062133396048626517150258702662", "1"], ["8850606065441144647949619181351959595003720725595390430819829661444282306718", "19665836002173232379511196796872951484491710163117072877825407241042584303231", "1"], ["14892327699421840970039260160003343983412842654133635495936741343100640885694", "3520701591340068807747882564141513192911405608895032049518054763667417126379", "1"], ["4481473648810633826017852905505390220138716225346811878089345709650646754602", "653493112683819332106307687595416593768673775438816115415109702223311584988", "1"], ["5291351803798825079882642997951567940128958498756023772953697302690583247549", "15118276314441535530812543933675573316737458529026081244165412909698332488213", "1"]]}`
)

// LevelsAtomicQuerySigCircuit is number of merkle tree levels credentialAttrQuerySig.circom compiled with
const LevelsAtomicQuerySigCircuit = 40

// ValueArraySizeAtomicQuerySigCircuit size of value array
const ValueArraySizeAtomicQuerySigCircuit = 16

// AtomicQuerySig represents credentialAtomicQueryMTP.circom
type AtomicQuerySig struct{}

// AtomicQuerySigInputs represents input data for kyc and kycBySignatures circuits
type AtomicQuerySigInputs struct {
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

	//
	SignatureProof BJJSignatureProof
	// query
	Query

	TypedInputs
}

// nolint // common approach to register default supported circuit
func init() {
	RegisterCircuit(AtomicQuerySigCircuitID, &AtomicQuerySig{})
}

// PrepareInputs returns inputs as a map for credentialAttrQuerySig.circom
func (c *AtomicQuerySig) PrepareInputs(in TypedInputs) (map[string]interface{}, error) {

	atomicInput, ok := in.(AtomicQuerySigInputs)
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

	signatureInput, err := c.prepareClaimIssuerSigInputs(&atomicInput.SignatureProof)
	if err != nil {
		return nil, err
	}

	return mergeMaps(claimInputs, authClaimInputs, queryInputs, signatureInput), nil
}

// PrepareRegularClaimInputs prepares inputs for regular claims
func (c *AtomicQuerySig) prepareRegularClaimInputs(claim Claim, rs RevocationStatus) (map[string]interface{}, error) {

	inputs := map[string]interface{}{
		"claim": bigIntArrayToStringArray(claim.Slots),
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

	inputs["claimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(rs.Proof.Siblings, LevelsAtomicQuerySigCircuit))

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
func (c *AtomicQuerySig) prepareAuthClaimInputs(in *AtomicQuerySigInputs) (map[string]interface{}, error) {

	if in.Signature == nil {
		return nil, errors.New("signature is null")
	}

	inputs := make(map[string]interface{})
	inputs["id"] = in.ID.BigInt().String()
	inputs["challenge"] = in.Challenge.String()

	inputs["authClaim"] = bigIntArrayToStringArray(in.AuthClaim.Slots)
	inputs["authClaimMtp"] = bigIntArrayToStringArray(
		PrepareSiblings(in.AuthClaim.Proof.Siblings, LevelsAtomicQuerySigCircuit))

	inputs["hoIdenState"] = in.CurrentStateTree.StateStr()
	inputs["hoClaimsTreeRoot"] = in.CurrentStateTree.ClaimsRootStr()
	inputs["hoRevTreeRoot"] = in.CurrentStateTree.RevocationRootStr()
	inputs["hoRootsTreeRoot"] = in.CurrentStateTree.RootOfRootsRootStr()

	inputs["authClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(in.AuthClaimRevStatus.Proof.Siblings, LevelsAtomicQuerySigCircuit))

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

// prepareClaimIssuerSigInputs prepare inputs for claim that is signed by issuer
func (c *AtomicQuerySig) prepareClaimIssuerSigInputs(in *BJJSignatureProof) (map[string]interface{}, error) {

	if in.Signature == nil {
		return nil, errors.New("signature is null")
	}

	inputs := make(map[string]interface{})
	inputs["issuerID"] = in.IssuerID.BigInt().String()

	inputs["issuerAuthClaimMtp"] = bigIntArrayToStringArray(
		PrepareSiblings(in.AuthClaimIssuerMTP.Siblings, LevelsAtomicQuerySigCircuit))

	inputs["issuerIdenState"] = in.IssuerTreeState.StateStr()
	inputs["issuerClaimsTreeRoot"] = in.IssuerTreeState.ClaimsRootStr()
	inputs["issuerRevTreeRoot"] = in.IssuerTreeState.RevocationRootStr()
	inputs["issuerRootsTreeRoot"] = in.IssuerTreeState.RootOfRootsRootStr()

	inputs["issuerAuthHi"] = in.HIndex.BigInt().String()
	inputs["issuerAuthHv"] = in.HValue.BigInt().String()
	inputs["issuerPubKeyX"] = in.IssuerPublicKey.X.String()
	inputs["issuerPubKeyY"] = in.IssuerPublicKey.Y.String()

	inputs["claimSignatureR8x"] = in.Signature.R8.X.String()
	inputs["claimSignatureR8y"] = in.Signature.R8.Y.String()
	inputs["claimSignatureS"] = in.Signature.S.String()

	return inputs, nil
}

func (c *AtomicQuerySig) prepareQueryInputs(in *AtomicQuerySigInputs) (map[string]interface{}, error) {
	inputs := make(map[string]interface{})
	inputs["slotIndex"] = in.Query.SlotIndex

	values, err := PrepareCircuitArrayValues(in.Query.Values, ValueArraySizeAtomicQuerySigCircuit)
	if err != nil {
		return nil, err
	}
	inputs["value"] = bigIntArrayToStringArray(values)
	inputs["operator"] = in.Query.Operator

	return inputs, nil
}

// GetVerificationKey returns verification key for circuit
func (c *AtomicQuerySig) GetVerificationKey() VerificationKeyJSON {
	return AtomicQuerySigVerificationKey
}

// GetPublicSignalsSchema returns schema to parse public inputs
func (c AtomicQuerySig) GetPublicSignalsSchema() PublicSchemaJSON {
	return AtomicQuerySigPublicSignalsSchema
}
