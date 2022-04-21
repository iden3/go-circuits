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
	AtomicQuerySigPublicSignalsSchema PublicSchemaJSON = `{"userID": 0, "userState": 1, "challenge": 2, 
"claimSchema": 3, "issuerID": 4,"issuerState":5, "slotIndex":6, "value_0": 7, "value_1": 8, "value_2": 9, 
"value_3": 10, "value_4": 11, "value_5": 12, "value_6": 13, "value_7": 14, "value_9": 15, "value_10": 16, 
"value_11": 17, "value_12": 18, "value_13": 19, "value_14": 20, "value_15": 21, "operator": 22, "timestamp": 23}`

	// AtomicQuerySigVerificationKey is verification key to verify credentialAttrQuerySig.circom
	AtomicQuerySigVerificationKey VerificationKeyJSON = `{"protocol":"groth16","curve":"bn128","nPublic":25,"vk_alpha_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["4708417253778585996843451787500730092783580236618941861605687897574506459914","4768674373558772979681807912113668478429156688325856406185089972058221350186"],["18720194752529848304359603889743279267615010775483089548493275119732267622413","9375671701761178493056366678261834193617698357117069242407984232614793802315"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["15240760668513665183481526215733583958325949168274748498803393343254130069319","11235022739170731628051173751385171152688897195653082273417003351537805878556","1"],["17157268506419230193059945504839159601386312395374814080507152353892444411014","21252835610157154775300849951460160642023699356576479270003789496664527728188","1"],["9478730063884741374600390567923665710874654166862197616977628778165585315904","10937287368373486404463917054376078853324729840080894985812181589274374036259","1"],["17312791393538661915425185800626666993681062508002139083568124022453036653025","4403390332174340198897297155365264510038767211557401006938277479569471707733","1"],["21336889733121202224689805527410401070608342965860500708573566304359514970354","11103809676923530815518828445896491085095116774246986158767930648174121896473","1"],["14769474375667028262458369345589799937244423036308258142468552889305202665488","587324023994914027062492209548742582202647294258890741737396520649422988538","1"],["13294747309708864323774540463050683224613275634622118855815498479449522432682","4029634969522342520344083902305666806912687871465631186970750812887858767200","1"],["17887051504316678859229148484335441880706823948710594492778022023579422084162","13059963478456561361938496169787126764943822580383853697706271862046145409741","1"],["18985582764060517165121776654845560620498508956527759807093177357022973167099","14463741308269794646385613698461948589440596764280182539678919898175415070028","1"],["10200961415079837606403585588716040203780547276370571615209271770050496000314","18831817845329400491843071129320178327461136194798528116917768338886729122469","1"],["1251304911061102201314616738473959893050291802635870101211738004031468653231","17454042539677120812391237257198180518064650737494518644840745521644675260490","1"],["1883770585325286180695502689777851256770280787395938421295045876703007811406","9292711251787944571226928451566218732611815965833392723773907716056332240826","1"],["13485443557812840971473834673575197588917340330225567756158003438000949845358","17775775736779813937579868140688839224978311015785405118206102221972973482990","1"],["1230134323345648436456938112348744604622251063456167422367503440102564125320","10176230337543470927161544707497685672263009680875005875887894956562193755181","1"],["17345199502854491816906246484587156480903331709495233907691053278144113527293","14802189729263366757990338145992456312294151830098262631614064884886603758598","1"],["1619080888813543863599032361848836870630638169688006567845673945128141427218","19743099933581374430377037247985920123159972006132510288257198891028301408885","1"],["16254281568571288095513999291869088998598056294628972615069140388826608252714","19526206401784055519064808836163888407709243174448981861701752806033057395412","1"],["5361538730496037421853135445702254266589434816541289719696073747440604559588","12430262528709352219602921665215148078325598920398733329441421353045530560625","1"],["11801968788413882943157605996180795967191775812891050513343386555975718914588","10325676143986239450593202930984542312269202985701224447299207353751232120691","1"],["5480151477992201779421826883633885855236467304285361163238638102268081026023","2604215366896449633109723412608481071735562860224293387996238518010296974268","1"],["4933696924514799158225088529717445133523189240936654538918983407600071341343","1013079039851858104093825300186782118685583466460000120833795204214036709585","1"],["12917831221016639597079836592117277429799857778114759376124712802864466970282","21598353947782660798809992142258021726288482737241672225999162890148933991457","1"],["3121700074741721071788722474999217060594523508989522302394959237768036374641","1973034567738344339904267293742136983566617316579716010780909424798659743219","1"],["11793891286710568479955982447681460555950180194201720873366036674637380669211","1793828904743777541924780717864140530578373069971646353571720250503868378947","1"],["12929143667520561578046201397791812268542923091245233550206134658286285870302","17838450060999061638964126149354902515513439266691164811280817867896893170136","1"],["14675604271768005641375381392011068239032092325522188728519271225620964203249","17680037555104842769291606073408602870589222302231860082661572295809468197377","1"]]}`
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

	// issuerClaim
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
func (c *AtomicQuerySig) prepareRegularClaimInputs(issuerClaim Claim, rs RevocationStatus) (map[string]interface{}, error) {

	inputs := map[string]interface{}{
		"issuerClaim": bigIntArrayToStringArray(issuerClaim.Slots),
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

	inputs["issuerClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(rs.Proof.Siblings, LevelsAtomicQuerySigCircuit))

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

	inputs["claimSchema"] = new(big.Int).SetBytes(issuerClaim.Schema[:]).String()
	inputs["timestamp"] = new(big.Int).SetInt64(issuerClaim.CurrentTimeStamp).String()

	return inputs, nil
}

// PrepareAuthClaimInputs prepare inputs for authorization (ID ownership)
func (c *AtomicQuerySig) prepareAuthClaimInputs(in *AtomicQuerySigInputs) (map[string]interface{}, error) {

	if in.Signature == nil {
		return nil, errors.New("signature is null")
	}

	inputs := make(map[string]interface{})
	inputs["userID"] = in.ID.BigInt().String()
	inputs["challenge"] = in.Challenge.String()

	inputs["userAuthClaim"] = bigIntArrayToStringArray(in.AuthClaim.Slots)
	inputs["userAuthClaimMtp"] = bigIntArrayToStringArray(
		PrepareSiblings(in.AuthClaim.Proof.Siblings, LevelsAtomicQuerySigCircuit))

	inputs["userState"] = in.CurrentStateTree.StateStr()
	inputs["userClaimsTreeRoot"] = in.CurrentStateTree.ClaimsRootStr()
	inputs["userRevTreeRoot"] = in.CurrentStateTree.RevocationRootStr()
	inputs["userRootsTreeRoot"] = in.CurrentStateTree.RootOfRootsRootStr()

	inputs["userAuthClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(in.AuthClaimRevStatus.Proof.Siblings, LevelsAtomicQuerySigCircuit))

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

// prepareClaimIssuerSigInputs prepare inputs for issuerClaim that is signed by issuer
func (c *AtomicQuerySig) prepareClaimIssuerSigInputs(in *BJJSignatureProof) (map[string]interface{}, error) {

	if in.Signature == nil {
		return nil, errors.New("signature is null")
	}

	inputs := make(map[string]interface{})
	inputs["issuerID"] = in.IssuerID.BigInt().String()

	inputs["issuerAuthClaimMtp"] = bigIntArrayToStringArray(
		PrepareSiblings(in.AuthClaimIssuerMTP.Siblings, LevelsAtomicQuerySigCircuit))

	inputs["issuerState"] = in.IssuerTreeState.StateStr()
	inputs["issuerClaimsTreeRoot"] = in.IssuerTreeState.ClaimsRootStr()
	inputs["issuerRevTreeRoot"] = in.IssuerTreeState.RevocationRootStr()
	inputs["issuerRootsTreeRoot"] = in.IssuerTreeState.RootOfRootsRootStr()

	inputs["issuerAuthHi"] = in.HIndex.BigInt().String()
	inputs["issuerAuthHv"] = in.HValue.BigInt().String()
	inputs["issuerPubKeyX"] = in.IssuerPublicKey.X.String()
	inputs["issuerPubKeyY"] = in.IssuerPublicKey.Y.String()

	inputs["issuerClaimSignatureR8x"] = in.Signature.R8.X.String()
	inputs["issuerClaimSignatureR8y"] = in.Signature.R8.Y.String()
	inputs["issuerClaimSignatureS"] = in.Signature.S.String()

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
