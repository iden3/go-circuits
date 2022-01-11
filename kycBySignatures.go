package circuits

import (
	"errors"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
	"math/big"
	"strconv"
)

const (
	// KycBySignaturesPublicSignalsSchema is schema to parse json data for additional information
	KycBySignaturesPublicSignalsSchema PublicSchemaJSON = `{"challenge":0,"user_identifier":1,"countryClaimIssuerId":2,"countryBlacklist_1":3,"countryBlacklist_2":4,"countryBlacklist_3":5,"countryBlacklist_4":6,"countryBlacklist_5":7,"countryBlacklist_6":8,"countryBlacklist_7":9,"countryBlacklist_8":10,"countryBlacklist_9":11,"countryBlacklist_10":12,"countryBlacklist_11":13,"countryBlacklist_12":14,"countryBlacklist_13":15,"countryBlacklist_14":16,"countryBlacklist_15":17,"countryBlacklist_16":18,"birthdayClaimIssuerId":19,"birthdayClaimIssuerBBJIdenState":20,"currentYear":21,"currentMonth":22,"currentDay":23}`

	// KycBySignaturesVerificationKey is verification key to verify kycBysSignature circuit
	KycBySignaturesVerificationKey VerificationKeyJSON = `{"protocol":"groth16","curve":"bn128","nPublic":24,"vk_alfa_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["14434206531747491757760934279315915125114909524034865934614578509984598471116","6829665911276683250889437702136606785828731910337170881639825025232470530937"],["20524900563047010900973910740802413806374302228044274085751908192478105281850","3527195989131407666221811629972221334093762800556674951851962866930681161459"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["2613754494873095081358459879636110064562899959645556781983817133181804357854","2804632039974425801582483876328358577924994672941220587010975678603335382555","1"],["2672160723030407374473245940491473345408893722026834954964981144999060898977","13918757694534624435689096953772082696641033253927789554291539155590124118534","1"],["6147027918533724553458164675020369700264289860155021612230798647414220072386","1387989772780016311432417108643853511049231175812121880400107772430348889686","1"],["6690244599375316908915505297827675281647150051492802647456232348123524121450","8305962816151986500069525221544364851852442574404925811595271841240453390096","1"],["12996003245003865002212925202202643450635829328965965202065038262990590489895","2672994542628372838904852003493912456940222700999029689115660910475189440327","1"],["13255668216778088892327570190873332651360617848329830873309196751817475617400","10166249287445410242210844360307513921003705443932613533620018556448002148361","1"],["19895120765096463512482155358745487178674255198488382363301256363430828909467","15987106223930326132505768875566999369312896874833027322947987509358695721194","1"],["19713383831717335331156130001399903387300715876417100393696657348022969981253","21814106296234742877713802609429714036271022928141360192240421365954530214291","1"],["2768373545428232906856314512957229911516617077626803067490352001914599802715","8546957994391630685608713644894106975986393788451843423660824751278076206895","1"],["10475548743287728057947949771317683469680725087441570120943304771379046572674","19624897274325155036626129875610757658490551688110318475729457130209909460860","1"],["8951386188114058462390337968510546818500212709818586321638328080909048582272","15720483255850640297573948670311464925440996781047476198093433468587347374098","1"],["12547176226585354902077368097192102536422244812508672108673287296503848683747","5223480295750887149378798174958861231565378002441347615231686053040783402423","1"],["12764038937833226591577498391875148532332489036013671594179675355820189206946","7756558629804815461705051019397867433626930042216544376975134930050089741158","1"],["5356246750679282654613243909016711037309244420377239669501705116841069478719","2824449118959702270920054237104739607944186041613161472548605093904659556694","1"],["9987173461751493529721796266384281608706526804291898100007693264850613933722","18270711296757673424266389107327216873820679070785083910386211760488314196445","1"],["9572671663206070105748470031480910506493380971559675451504015956545332366292","13882265579534090584775853788961233092222175802349611491798450062966779373337","1"],["12808096759897249618309628114910943665729789012304709897198858107499452602490","10285489886246827681841938844087612261857843429298697381800891283230752875680","1"],["15334629989394487740419774675946195107231409461718252273011049622742481053173","17117018223174709436295767946952395671950571124738078433324853250892594926429","1"],["21028917070638205319186798462233567957269946181130132538899521044383246878018","11667122644452475096320368936037036345333649094281073925950839041578316346274","1"],["3898544872330699054258080874325067404451252101600411423497432095660933201064","18620901959691018132332949441853442603643191174357316998298458807281605149891","1"],["11014871699293611687844334164787594521764016097045321064638320573296004588152","5218929655269052455924559927679511628657965837279820619692347040155401649549","1"],["1387031631571373031465159911420945259085706612709926672216663272751770337486","5710568483881711086301671442260827568127349191039752126161414987183134772847","1"],["8182514255398509617487632779802118729265805138337912672254229810537101415706","6955624511675027822466693154381500416019968873173069523473525882555066658117","1"],["9519491498270093212629898116669742183228076114079034869898583548327910674386","9288043874288300341169753136264797947545332453427528379094428931466805309862","1"],["5656147116879710821770237204459105766342758633513727643827830894062990913415","12638859992611960648006416613145767088445410577572820405562267322925344468078","1"]]}`
)

// KYCBySignatures represents KycBySignatures circuit
type KYCBySignatures struct {
}

// nolint // common approach to register default supported circuit
func init() {
	RegisterCircuit(KycBySignaturesCircuitID, &KYCBySignatures{})
}

// GetVerificationKey returns verification key
func (c *KYCBySignatures) GetVerificationKey() VerificationKeyJSON {
	return KycBySignaturesVerificationKey
}

// GetPublicSignalsSchema returns schema to parse public signals
func (c *KYCBySignatures) GetPublicSignalsSchema() PublicSchemaJSON {
	return KycBySignaturesPublicSignalsSchema
}

// PrepareInputs rerurns inputs for circuit KycBySignatures
func (c *KYCBySignatures) PrepareInputs(in TypedInputs) (map[string]interface{}, error) {

	kycInputs, ok := in.(KYCBySignaturesInputs)
	if !ok {
		return nil, errors.New("wrong type of input arguments")
	}
	ageClaimInputs, err := c.prepareRegularClaimInputs(
		kycInputs.KYCAgeCredential, kycInputs.KYCAgeCredentialRevocationStatus,
		"birthday", kycInputs.AgeSignatureProof)
	if err != nil {
		return nil, err
	}
	countryClaimInputs, err := c.prepareRegularClaimInputs(
		kycInputs.KYCCountryOfResidenceCredential,
		kycInputs.KYCCountryOfResidenceRevocationStatus, "country",
		kycInputs.CountrySignatureProof)
	if err != nil {
		return nil, err
	}

	authClaimInputs, err := c.prepareAuthClaimInputs(&kycInputs)
	if err != nil {
		return nil, err
	}

	publicInputs, err := c.prepareCircuitPublicInputs(kycInputs.Rules)
	if err != nil {
		return nil, err
	}
	inputs := mergeMaps(ageClaimInputs, countryClaimInputs, authClaimInputs, publicInputs)
	return inputs, nil
}

type SignatureProof interface {
	signatureProofMarker()
}

type BaseSignatureProof struct {
	IssuerID        *core.ID
	IssuerTreeState TreeState
	Siblings        []*merkletree.Hash
}

type BJJSignatureProof struct {
	BaseSignatureProof
	IssuerPublicKey *babyjub.PublicKey
	Signature       *babyjub.Signature
}

func (BJJSignatureProof) signatureProofMarker() {}

// prepareRegularClaimInputs prepares inputs for regular claims
func (c *KYCBySignatures) prepareRegularClaimInputs(claim Claim,
	rs RevocationStatus, fieldName string,
	signatureProof2 SignatureProof) (map[string]interface{}, error) {

	inputs := make(map[string]interface{})
	var err error

	inputs[fieldName+"Claim"] = bigIntArrayToStringArray(claim.Slots)

	switch sp := signatureProof2.(type) {
	case BJJSignatureProof:
		inputs[fieldName+"ClaimIssuerBBJClaimMtp"] = bigIntArrayToStringArray(
			PrepareSiblings(sp.Siblings, LevelsKYCCircuits))
		inputs[fieldName+"ClaimIssuerBBJAx"] = sp.IssuerPublicKey.X.String()
		inputs[fieldName+"ClaimIssuerBBJAy"] = sp.IssuerPublicKey.Y.String()
		inputs[fieldName+"ClaimSignatureR8x"] = sp.Signature.R8.X.String()
		inputs[fieldName+"ClaimSignatureR8y"] = sp.Signature.R8.Y.String()
		inputs[fieldName+"ClaimSignatureS"] = sp.Signature.S.String()
		// Issuer identifier
		inputs[fieldName+"ClaimIssuerId"] = sp.IssuerID.BigInt().String()
		inputs[fieldName+"ClaimIssuerBBJClaimClaimsTreeRoot"] = sp.
			IssuerTreeState.ClaimsRootStr()
		inputs[fieldName+"ClaimIssuerBBJClaimRevTreeRoot"] = sp.
			IssuerTreeState.RevocationRootStr()
		inputs[fieldName+"ClaimIssuerBBJClaimRootsTreeRoot"] = sp.
			IssuerTreeState.RootOfRootsRootStr()
		inputs[fieldName+"ClaimIssuerBBJIdenState"] = sp.
			IssuerTreeState.StateStr()
	default:
		return nil, errors.New("signature type is not supported")
	}

	err = handleRevocationStateInputs(rs, fieldName, inputs)
	if err != nil {
		return nil, err
	}

	return inputs, nil
}

// prepareAuthClaimInputs prepare inputs for authorization (ID ownership)
func (c *KYCBySignatures) prepareAuthClaimInputs(in *KYCBySignaturesInputs) (map[string]interface{}, error) {

	inputs := make(map[string]interface{})
	inputs["id"] = in.ID.BigInt().String()
	inputs["challenge"] = strconv.FormatInt(in.Challenge, 10)
	inputs["BBJClaimMtp"] = bigIntArrayToStringArray(
		PrepareSiblings(in.AuthClaim.Proof.Siblings, 4))
	inputs["BBJClaimClaimsTreeRoot"] = in.AuthClaim.TreeState.ClaimsRoot.BigInt().String()
	inputs["BBJAx"] = in.AuthClaim.Slots[2].String()
	inputs["BBJAy"] = in.AuthClaim.Slots[3].String()
	inputs["challengeSignatureR8x"] = in.Signature.R8.X.String()
	inputs["challengeSignatureR8y"] = in.Signature.R8.Y.String()
	inputs["challengeSignatureS"] = in.Signature.S.String()

	inputs["BBJClaimRevTreeRoot"] = in.AuthClaim.TreeState.RevocationRootStr()
	inputs["BBJClaimRootsTreeRoot"] = in.AuthClaim.TreeState.RootOfRootsRootStr()

	return inputs, nil
}

// prepareCircuitPublicInputs prepares input for public rules
// nolint:dupl // allows to change public inputs for circuit later
func (c *KYCBySignatures) prepareCircuitPublicInputs(rules map[string]interface{}) (map[string]interface{}, error) {

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

// KYCBySignaturesInputs represents input data for kyc and kycBySignatures circuits
type KYCBySignaturesInputs struct {
	KYCAgeCredential                      Claim
	KYCAgeCredentialRevocationStatus      RevocationStatus
	AgeSignatureProof                     SignatureProof
	KYCCountryOfResidenceCredential       Claim
	KYCCountryOfResidenceRevocationStatus RevocationStatus
	CountrySignatureProof                 SignatureProof

	ID        *core.ID
	Challenge int64
	Signature *babyjub.Signature
	AuthClaim Claim

	Rules map[string]interface{}

	TypedInputs
}
