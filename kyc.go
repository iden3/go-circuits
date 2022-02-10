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
	// KycPublicSignalsSchema is schema to parse json data for additional information
	KycPublicSignalsSchema PublicSchemaJSON = `{"user_identifier":0,"challenge":1,"countryClaimIssuerId":2,"countryClaimIssuerBBJIdenState":3,"countryBlacklist_1":4,"countryBlacklist_2":5,"countryBlacklist_3":6,"countryBlacklist_4":7,"countryBlacklist_5":8,"countryBlacklist_6":9,"countryBlacklist_7":10,"countryBlacklist_8":11,"countryBlacklist_9":12,"countryBlacklist_10":13,"countryBlacklist_11":14,"countryBlacklist_12":15,"countryBlacklist_13":16,"countryBlacklist_14":17,"countryBlacklist_15":18,"countryBlacklist_16":19,"birthdayClaimIssuerId":20,"birthdayClaimIssuerBBJIdenState":21,"currentYear":22,"currentMonth":23,"currentDay":24,"minAge":25}`

	// KycVerificationKey is verification key to verify kycBysSignature circuit
	KycVerificationKey VerificationKeyJSON = `{"protocol":"groth16","curve":"bn128","nPublic":26,"vk_alpha_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["2890198598876221093448981733612624180034354817429708453677892392386499741259","2786109982182567284336731734113201787122924108524180374998095628353868702716"],["7547015666571679909628799912505335447687018709486488094448978042650699113695","6513902242930199306731205712034035619211099946192026052332984625901600575611"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["9908916185707734229758339290943427585946984012391232040852775121573876325566","13922926774125946704009842529417264211960523643995558081273196533795265800887","1"],["740585572957162183312062054382598973402585420692140027035532355927910903520","6184541446242829343759333190377737787623113948173036784795716380087569106549","1"],["8826034502417054954655381840552043974542077908160383403580743698513493514991","15275104580046471966077082756307410008480764111646990304174669495896009744022","1"],["4441375505773935164281106987458341706087947927483729562612239300318816723050","9913249832308633067544262926331740799572202531385971087211352029749988001902","1"],["19105142854863326090306452022708538470133667271142372356094164736125494416873","4590261757348463434051064247812198028388465415666263298020616708608706259516","1"],["4786105784531230103952148710454053950841412564249854263810067356890266486610","16595775962850729197203851358238668153529769395985589906114606714140895556261","1"],["16069900506807412608502284222485965587894451606920606890665795939893309251968","17005789777178679982750586326170896965749259422003830292532956343536210490715","1"],["3516140267790424652668587543164577062324399167866845415031578788766414665018","4366379258003265981930683954159146770276108974364921699942070723375304286577","1"],["9244760543939628640046551839290544427886147916306393702534379494428469126574","14516512404232655000442068024413133444911709843077690592988195663584757833912","1"],["3866095017093477646788351696136676624735079954829180382061733971893983842644","4612891621821170997070648073383999921245810059024013548071440174028657005527","1"],["19482473842786712450723436150363059617221929778452910657479198283901381504141","4043752875742714266303587892970643853967084693737227060767646328381956151322","1"],["430703865760485388489958091226092468919214249139211613032315709822194786655","8929636635975611495829139402721756333155595826888692582930221138412664976342","1"],["14782763078760722463030986155636352051484892338358932272265417100717999769058","16908623635902344075522831366778941122719317128264596068014765604636932982007","1"],["9312086249638504925630832440006453378578005755830427294828320797290626732407","4048747992378680180826922213622838332382389534699043294404410617107344735579","1"],["17746653160979928811459299012461251558487677618736646801633859974653524424867","7737430071433925711245333181389041440183070045169905391992821403165708983140","1"],["969634726988253701217072683673453082356868867943745985951334014425894466917","2323962548297127612575956266875311664268445249521463927346123564458939295502","1"],["7204025277818329423597912188572076221590294971629675195775864498364110180641","16957114147422966310289500359251224929608973677797937878347099770104995620042","1"],["12454575035075918329509920216904221671505776829360968253912181213428731211794","14994573595099624448996151239585313963377652525807859352775366463201528780751","1"],["16362281370479526586398447231076814372992190023299939768348315307124044732933","2897084659738525826915838607826670705989080033867463581303152726882832589691","1"],["656233340403812830748776191341629171858217993806019536677362940235791103974","7415392699584835192235734279827685756305407451806653493521506795846134183543","1"],["13374988735785725260959221583713148827091186227020320617653001255618747710680","17532774836254208000954599305578858705212574921814098617201392918853618634454","1"],["821084727135884668218686133257772322596703285048232507459269002090580759403","72470325331007028718743519422527312700703302614775624442777504758475438935","1"],["15384363840921171820120865073299509812098042839748033981829026788505569227548","10043735654863048381988729429477387011209786842484085844144545361324964509773","1"],["18408620018344830217298466553634457507207927828857075210677886440184056766038","15200486961738482632278833248100548741432001716606656462659059594336625665238","1"],["3004855486622093434572732153524483675253474502880841609470874476688924931685","12842012092083642790991536245048914506792169824200750935913849796306128458143","1"],["11729045354368531754490974815449394019335127243795382575309124674238207185394","3585505230945004430223775677390812848258105376821010745309414127381812312281","1"],["21790833697886695001253561766481507068780310659633907672437242632386621895107","17872202141300613905315284015350023455222027916601315653361320248480721952971","1"]]}`
)

// LevelsKYCCircuits is number of levels currently used in KYC circuits
const LevelsKYCCircuits = 40

// KYC represents kyc circuit
type KYC struct {
}

// nolint // common approach to register default supported circuit
func init() {
	RegisterCircuit(KycCircuitCircuitID, &KYC{})
}

// PrepareInputs returns inputs as a map for kyc circuit
func (c *KYC) PrepareInputs(in TypedInputs) (map[string]interface{}, error) {

	kycInputs, ok := in.(KYCInputs)
	if !ok {
		return nil, errors.New("wrong type of input arguments")
	}
	ageClaimInputs, err := c.prepareRegularClaimInputs(kycInputs.KYCAgeCredential, kycInputs.KYCAgeCredentialRevocationStatus, "birthday")
	if err != nil {
		return nil, err
	}
	countryClaimInputs, err := c.prepareRegularClaimInputs(kycInputs.KYCCountryOfResidenceCredential, kycInputs.KYCCountryOfResidenceRevocationStatus, "country")
	if err != nil {
		return nil, err
	}

	authClaimInputs := c.prepareAuthClaimInputs(&kycInputs)

	publicInputs, err := c.prepareCircuitPublicInputs(kycInputs.Rules)
	if err != nil {
		return nil, err
	}
	inputs := mergeMaps(ageClaimInputs, countryClaimInputs, authClaimInputs, publicInputs)
	return inputs, nil
}

type Claim struct {
	Schema           core.SchemaHash
	Slots            []*big.Int
	Proof            Proof
	TreeState        TreeState
	CurrentTimeStamp int64
	IssuerID         *core.ID
}

type NodeAux struct {
	HIndex *merkletree.Hash
	HValue *merkletree.Hash
}

type Proof struct {
	Siblings []*merkletree.Hash
	NodeAux  *NodeAux
}

// PrepareRegularClaimInputs prepares inputs for regular claims
func (c *KYC) prepareRegularClaimInputs(claim Claim, rs RevocationStatus,
	fieldName string) (map[string]interface{}, error) {

	inputs := map[string]interface{}{
		fieldName + "Claim": bigIntArrayToStringArray(claim.Slots),
		fieldName + "ClaimIssuanceMtp": bigIntArrayToStringArray(
			PrepareSiblings(claim.Proof.Siblings, LevelsKYCCircuits)),
		fieldName + "ClaimIssuanceClaimsTreeRoot": claim.TreeState.
			ClaimsRootStr(),
		fieldName + "ClaimIssuanceRevTreeRoot": claim.TreeState.
			RevocationRootStr(),
		fieldName + "ClaimIssuanceRootsTreeRoot": claim.TreeState.
			RootOfRootsRootStr(),
		fieldName + "ClaimIssuanceIdenState": claim.TreeState.StateStr(),
	}

	if err := handleRevocationStateInputs(rs, fieldName, inputs); err != nil {
		return nil, err
	}

	return inputs, nil
}

// PrepareAuthClaimInputs prepare inputs for authorization (ID ownership)
func (c *KYC) prepareAuthClaimInputs(in *KYCInputs) map[string]interface{} {

	inputs := make(map[string]interface{})
	inputs["id"] = in.ID.BigInt().String()
	inputs["challenge"] = strconv.FormatInt(in.Challenge, 10)
	inputs["BBJClaimMtp"] = bigIntArrayToStringArray(
		PrepareSiblings(in.AuthClaim.Proof.Siblings, 4))
	inputs["BBJClaimClaimsTreeRoot"] = in.AuthClaim.TreeState.ClaimsRoot.BigInt().String()
	inputs["userPrivateKey"] = (*big.Int)(in.PK.Scalar()).String()

	return inputs
}

// PrepareCircuitPublicInputs prepares input for public rules
// nolint:dupl // allows to change public inputs for circuit later
func (c *KYC) prepareCircuitPublicInputs(rules map[string]interface{}) (map[string]interface{}, error) {

	inputs := make(map[string]interface{})

	countryBlackList, ok := rules["countryBlacklist"]
	if !ok {
		return nil, errors.New("country list is not provided in rules argument")
	}
	countryCodes := make([]*big.Int, 16)
	for i := range countryCodes {
		countryCodes[i] = new(big.Int).SetInt64(0)
	}
	for i, code := range countryBlackList.([]interface{}) {
		countryCodes[i] = new(big.Int).SetInt64(int64(code.(float64)))
	}
	inputs["countryBlacklist"] = bigIntArrayToStringArray(countryCodes)

	currentYear, ok := rules["currentYear"].(float64)
	if !ok {
		return nil, errors.New("currentYear is not provided in rules argument")
	}
	currentMonth, ok := rules["currentMonth"].(float64)
	if !ok {
		return nil, errors.New("currentMonth is not provided in rules argument")
	}
	currentDay, ok := rules["currentDay"].(float64)
	if !ok {
		return nil, errors.New("currentDay is not provided in rules argument")
	}

	minAge, ok := rules["minAge"].(float64)
	if !ok {
		return nil, errors.New("minAge is not provided in rules argument")
	}

	inputs["currentYear"] = new(big.Int).SetInt64(int64(currentYear)).String()
	inputs["currentMonth"] = new(big.Int).SetInt64(int64(currentMonth)).String()
	inputs["currentDay"] = new(big.Int).SetInt64(int64(currentDay)).String()
	inputs["minAge"] = new(big.Int).SetInt64(int64(minAge)).String()

	return inputs, nil
}

// KYCInputs represents input data for kyc and kycBySignatures circuits
type KYCInputs struct {
	KYCAgeCredential                      Claim
	KYCAgeCredentialRevocationStatus      RevocationStatus
	KYCCountryOfResidenceCredential       Claim
	KYCCountryOfResidenceRevocationStatus RevocationStatus
	ID                                    *core.ID
	PK                                    *babyjub.PrivateKey
	Challenge                             int64
	TypedInputs

	AuthClaim Claim

	Rules map[string]interface{}
}

// GetVerificationKey returns verification key for circuit
func (c *KYC) GetVerificationKey() VerificationKeyJSON {
	return KycVerificationKey
}

// GetPublicSignalsSchema returns schema to parse public inputs
func (c KYC) GetPublicSignalsSchema() PublicSchemaJSON {
	return KycPublicSignalsSchema
}

func handleMTPInputs(mtp Proof, fieldName string, inputs map[string]interface{}) (err error) {

	inputs[fieldName+"ClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(mtp.Siblings, LevelsKYCCircuits))

	if mtp.NodeAux == nil {
		inputs[fieldName+"ClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		inputs[fieldName+"ClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		inputs[fieldName+"ClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(1).String() // (yes it's isOld = 1) // TODO: clarify with Jordi
		return nil
	}
	inputs[fieldName+"ClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(0).String() // (no it's isOld = 0)
	if mtp.NodeAux.HIndex == nil {
		inputs[fieldName+"ClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
	} else {
		inputs[fieldName+"ClaimNonRevMtpAuxHi"] = mtp.NodeAux.HIndex.BigInt().String()
	}
	if mtp.NodeAux.HValue == nil {
		inputs[fieldName+"ClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
	} else {
		inputs[fieldName+"ClaimNonRevMtpAuxHv"] = mtp.NodeAux.HValue.BigInt().String()
	}

	return nil
}

type TreeState struct {
	State          *merkletree.Hash
	ClaimsRoot     *merkletree.Hash
	RevocationRoot *merkletree.Hash
	RootOfRoots    *merkletree.Hash
}

func (ts TreeState) StateStr() string {
	if ts.State == nil {
		return merkletree.HashZero.BigInt().String()
	}
	return ts.State.BigInt().String()
}

func (ts TreeState) ClaimsRootStr() string {
	if ts.ClaimsRoot == nil {
		return merkletree.HashZero.BigInt().String()
	}
	return ts.ClaimsRoot.BigInt().String()
}

func (ts TreeState) RevocationRootStr() string {
	if ts.RevocationRoot == nil {
		return merkletree.HashZero.BigInt().String()
	}
	return ts.RevocationRoot.BigInt().String()
}

func (ts TreeState) RootOfRootsRootStr() string {
	if ts.RootOfRoots == nil {
		return merkletree.HashZero.BigInt().String()
	}
	return ts.RootOfRoots.BigInt().String()
}

type RevocationStatus struct {
	TreeState TreeState
	Proof     Proof
}

func handleRevocationStateInputs(rs RevocationStatus, fieldName string,
	inputs map[string]interface{}) error {
	inputs[fieldName+"ClaimNonRevIssuerState"] = rs.TreeState.StateStr()
	inputs[fieldName+"ClaimNonRevIssuerRootsTreeRoot"] = rs.TreeState.
		RootOfRootsRootStr()
	inputs[fieldName+"ClaimNonRevIssuerRevTreeRoot"] = rs.TreeState.
		RevocationRootStr()
	inputs[fieldName+"ClaimNonRevIssuerClaimsTreeRoot"] = rs.TreeState.
		ClaimsRootStr()
	return handleMTPInputs(rs.Proof, fieldName, inputs)
}
