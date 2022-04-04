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
"issuerClaimSchema": 3, "issuerID": 4,"issuerState":5, "slotIndex":6, "value_0": 7, "value_1": 8, "value_2": 9, 
"value_3": 10, "value_4": 11, "value_5": 12, "value_6": 13, "value_7": 14, "value_9": 15, "value_10": 16, 
"value_11": 17, "value_12": 18, "value_13": 19, "value_14": 20, "value_15": 21, "operator": 22, "timestamp": 23}`

	// AtomicQuerySigVerificationKey is verification key to verify credentialAttrQuerySig.circom
	AtomicQuerySigVerificationKey VerificationKeyJSON = `{"protocol":"groth16","curve":"bn128","nPublic":25,"vk_alpha_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["4030889886527512927464489055778264195026327234344297329342574846571936375898","14679058152716502380097457001792988184266869011990821865455662930903546850499"],["15008923684120398980662519594804495252525764101488973995091971434530983272559","18253284413000287008485064683989995992720787829777701786643516172423024866523"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["19358840197597499801228573201449916612352532020047381950057569384056591767602","18822778438282039087227631250754800611734737028272198362848147369016099576426","1"],["7604349467235969496812902114804321724079908709527091126435191176459020095036","14202083016402639456079115850797030575991875677362031932625634375758122738195","1"],["6284727474239620201158905598814505717708087424179647049535918547117243606885","7456246283321857075887721082686835929349887506557757694475846374244369570776","1"],["19661232049808231768547595122515368739753334205778196998816684092362647730235","19352215016062691090629847726765948244047816045874045574056673654531115181617","1"],["19324117217954813614637707009324012953415474208590015923498288516428101333104","9898726713196193623008699724210699580248246556499599778497872407618041888102","1"],["8492003098768606602399452070022052644568932813259193484071156802420511747152","19156039892547798332433257444310851675493901779958345335649732723536145808425","1"],["3863751351332911753697485794781960795455642725635961864680992553970267128983","4290595758030953583566154348695379802288573941790214014051456140203222720313","1"],["13538534291726578764856457449745280381867869722473101226969568164512376690778","12624166342550172446857999470683649726457216071747371188176054278953908288997","1"],["830120411425776703392225538088474683797236214464649578782426194731230616438","5719248764611631803760822047741935576343442703994617028776555555510709882467","1"],["5672571715208574589092035087096346121071911881655663969906697045716501866375","1332132985843167617915005971870058587343676597725244455012295844091311383928","1"],["1607869602938675826720738264539937308739469678636032199590453702910740973572","4088617721088681842535065752101405135079969275445763593706022660141189374247","1"],["2122164324480577677984899842541961790605436966771556505820462477458289424415","5949962449355965195385156798854871272707694295242552314330385829087554963381","1"],["18704261872688712480542538734347876873102354055861443741860823716193960410913","13376245200435168667332133389205367813862628801923622212449856190796934445761","1"],["20025823515171037871650203631854653431995828568521110523971129948215545456234","4070040873160799841429818582653597270309770995025469251394368497551071293287","1"],["21844262429035425769597626090987622291719424983338924589502341368176525562709","10785699587361703609322350524786498500219157640356753282500710050476489907756","1"],["16525211849242361108694302862077499825704280077577893900312117802295271211808","19275460264680298732300020287922678800605323797992348908937019541451077340752","1"],["2077664423820180957188707533848405322135181578027401907588806639361167714477","2505818974640155138007052491341350870055432401181029260903547217788055918575","1"],["2945333398086504563512979432196074503374734888197110272361174704461925773616","7348924755105531959493486666989416935283974264965113682182631313216940733238","1"],["591969280482561483202327762793580727874835803022899846175312940081121127849","17787300778509746536074067182559367738305191497513235002461130227179949900449","1"],["17986703855705293135590007961155042293475265279715726267696443956550095661460","6963830823666215446191186638866841037445864026249882512951549197225079568385","1"],["13836256541867762230401962256378960545574806420577750884656078399133853726956","18999562270967523879578478189663118789783015267768695596908208188771164541670","1"],["18859185232389566198700759206242631430203694357200560813309298852805888622252","1499357988538409584701964090717196447124587823213833132139706890987070602859","1"],["16721505530199685333838141098952018689602832287632543418479221206363888861492","19280020160574311158036227346075742078113440377493759148163671706691874537210","1"],["12466168921606684391997562942236086866982956536216418073904061823114760549207","15355708241605229135110172028520883755635252829982382289910002999975499725503","1"],["10163842672858939506823927936106561870158445838300552083178092884054690398017","12572102581685413920519981893499461971583631992332002976076972691630866255841","1"],["16879229262584565164920654096554499867968635862232747139965668550295261989559","12769123531704735505692279475948357023014785639913034968842550605513424028869","1"]]}`
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

	inputs["issuerClaimSchema"] = new(big.Int).SetBytes(issuerClaim.Schema[:]).String()
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
