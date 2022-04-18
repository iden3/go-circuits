package circuits

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"

	"github.com/fatih/structs"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
)

const (
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
	ID        *core.ID
	AuthClaim Claim
	Challenge *big.Int
	Signature *babyjub.Signature

	// issuerClaim
	Claim
	//RevocationStatus

	// query
	Query

	CurrentTimeStamp int64
	Schema           core.SchemaHash

	CircuitMarshaller
}

type atomicQuerySigCircuitInputs struct {
	UserAuthClaim               *core.Claim      `json:"userAuthClaim"`
	UserAuthClaimMtp            []string         `json:"userAuthClaimMtp"`
	UserAuthClaimNonRevMtp      []string         `json:"userAuthClaimNonRevMtp"`
	UserAuthClaimNonRevMtpAuxHi *merkletree.Hash `json:"userAuthClaimNonRevMtpAuxHi"`
	UserAuthClaimNonRevMtpAuxHv *merkletree.Hash `json:"userAuthClaimNonRevMtpAuxHv"`
	UserAuthClaimNonRevMtpNoAux string           `json:"userAuthClaimNonRevMtpNoAux"`
	UserClaimsTreeRoot          *merkletree.Hash `json:"userClaimsTreeRoot"`
	UserState                   *merkletree.Hash `json:"userState"`
	UserRevTreeRoot             *merkletree.Hash `json:"userRevTreeRoot"`
	UserRootsTreeRoot           *merkletree.Hash `json:"userRootsTreeRoot"`
	UserID                      string           `json:"userID"`

	Challenge             string `json:"challenge"`
	ChallengeSignatureR8X string `json:"challengeSignatureR8x"`
	ChallengeSignatureR8Y string `json:"challengeSignatureR8y"`
	ChallengeSignatureS   string `json:"challengeSignatureS"`

	IssuerClaim                     *core.Claim      `json:"issuerClaim"`
	IssuerClaimNonRevClaimsTreeRoot *merkletree.Hash `json:"issuerClaimNonRevClaimsTreeRoot"`
	IssuerClaimNonRevRevTreeRoot    *merkletree.Hash `json:"issuerClaimNonRevRevTreeRoot"`
	IssuerClaimNonRevRootsTreeRoot  *merkletree.Hash `json:"issuerClaimNonRevRootsTreeRoot"`
	IssuerClaimNonRevState          *merkletree.Hash `json:"issuerClaimNonRevState"`
	IssuerClaimNonRevMtp            []string         `json:"issuerClaimNonRevMtp"`
	IssuerClaimNonRevMtpAuxHi       *merkletree.Hash `json:"issuerClaimNonRevMtpAuxHi"`
	IssuerClaimNonRevMtpAuxHv       *merkletree.Hash `json:"issuerClaimNonRevMtpAuxHv"`
	IssuerClaimNonRevMtpNoAux       string           `json:"issuerClaimNonRevMtpNoAux"`
	ClaimSchema                     string           `json:"claimSchema"`
	IssuerID                        string           `json:"issuerID"`
	Operator                        int              `json:"operator"`
	SlotIndex                       int              `json:"slotIndex"`
	Timestamp                       int64            `json:"timestamp,string"`
	Value                           []string         `json:"value"`

	IssuerClaimSignatureR8X string           `json:"issuerClaimSignatureR8x"`
	IssuerClaimSignatureR8Y string           `json:"issuerClaimSignatureR8y"`
	IssuerClaimSignatureS   string           `json:"issuerClaimSignatureS"`
	IssuerAuthClaimMtp      []string         `json:"issuerAuthClaimMtp"`
	IssuerAuthHi            string           `json:"issuerAuthHi"`
	IssuerAuthHv            string           `json:"issuerAuthHv"`
	IssuerClaimsTreeRoot    *merkletree.Hash `json:"issuerClaimsTreeRoot"`
	IssuerState             *merkletree.Hash `json:"issuerState"`
	IssuerPubKeyX           string           `json:"issuerPubKeyX"`
	IssuerPubKeyY           string           `json:"issuerPubKeyY"`
	IssuerRevTreeRoot       *merkletree.Hash `json:"issuerRevTreeRoot"`
	IssuerRootsTreeRoot     *merkletree.Hash `json:"issuerRootsTreeRoot"`
}

func (a AtomicQuerySigInputs) CircuitMarshal() ([]byte, error) {

	s := atomicQuerySigCircuitInputs{
		UserAuthClaim: a.AuthClaim.Claim,
		UserAuthClaimMtp: PrepareSiblingsStr(a.AuthClaim.Proof.AllSiblings(),
			LevelsAtomicQueryMTPCircuit),
		UserAuthClaimNonRevMtp: PrepareSiblingsStr(a.AuthClaim.NonRevProof.Proof.AllSiblings(),
			LevelsAtomicQueryMTPCircuit),
		Challenge:                       a.Challenge.String(),
		ChallengeSignatureR8X:           a.Signature.R8.X.String(),
		ChallengeSignatureR8Y:           a.Signature.R8.Y.String(),
		ChallengeSignatureS:             a.Signature.S.String(),
		IssuerClaim:                     a.Claim.Claim,
		IssuerClaimNonRevClaimsTreeRoot: a.Claim.NonRevProof.TreeState.ClaimsRoot,
		IssuerClaimNonRevRevTreeRoot:    a.Claim.NonRevProof.TreeState.RevocationRoot,
		IssuerClaimNonRevRootsTreeRoot:  a.Claim.NonRevProof.TreeState.RootOfRoots,
		IssuerClaimNonRevState:          a.Claim.NonRevProof.TreeState.State,
		IssuerClaimNonRevMtp: PrepareSiblingsStr(a.Claim.NonRevProof.Proof.AllSiblings(),
			LevelsAtomicQueryMTPCircuit),
		ClaimSchema:             new(big.Int).SetBytes(a.Schema[:]).String(),
		UserClaimsTreeRoot:      a.AuthClaim.TreeState.ClaimsRoot,
		UserState:               a.AuthClaim.TreeState.State,
		UserRevTreeRoot:         a.AuthClaim.TreeState.RevocationRoot,
		UserRootsTreeRoot:       a.AuthClaim.TreeState.RootOfRoots,
		UserID:                  a.ID.BigInt().String(),
		IssuerID:                a.IssuerID.BigInt().String(),
		Operator:                a.Operator,
		SlotIndex:               a.SlotIndex,
		Timestamp:               a.CurrentTimeStamp,
		IssuerClaimSignatureR8X: a.SignatureProof.Signature.R8.X.String(),
		IssuerClaimSignatureR8Y: a.SignatureProof.Signature.R8.Y.String(),
		IssuerClaimSignatureS:   a.SignatureProof.Signature.S.String(),

		IssuerAuthClaimMtp: bigIntArrayToStringArray(
			PrepareSiblings(a.SignatureProof.AuthClaimIssuerMTP.AllSiblings(), LevelsAtomicQuerySigCircuit)),
		IssuerAuthHi:         a.SignatureProof.HIndex.BigInt().String(),
		IssuerAuthHv:         a.SignatureProof.HValue.BigInt().String(),
		IssuerClaimsTreeRoot: a.SignatureProof.IssuerTreeState.ClaimsRoot,
		IssuerState:          a.SignatureProof.IssuerTreeState.State,
		IssuerPubKeyX:        a.SignatureProof.IssuerPublicKey.X.String(),
		IssuerPubKeyY:        a.SignatureProof.IssuerPublicKey.Y.String(),
		IssuerRevTreeRoot:    a.SignatureProof.IssuerTreeState.RevocationRoot,
		IssuerRootsTreeRoot:  a.SignatureProof.IssuerTreeState.RootOfRoots,
	}

	values, err := PrepareCircuitArrayValues(a.Values, ValueArraySizeAtomicQuerySigCircuit)
	if err != nil {
		return nil, err
	}
	s.Value = bigIntArrayToStringArray(values)

	nodeAuxAuth := getNodeAuxValue(a.Claim.NonRevProof.Proof.NodeAux)
	s.UserAuthClaimNonRevMtpAuxHi = nodeAuxAuth.key
	s.UserAuthClaimNonRevMtpAuxHv = nodeAuxAuth.value
	s.UserAuthClaimNonRevMtpNoAux = nodeAuxAuth.noAux

	nodeAux := getNodeAuxValue(a.Claim.NonRevProof.Proof.NodeAux)
	s.IssuerClaimNonRevMtpAuxHi = nodeAux.key
	s.IssuerClaimNonRevMtpAuxHv = nodeAux.value
	s.IssuerClaimNonRevMtpNoAux = nodeAux.noAux

	return json.Marshal(s)
}

// nolint // common approach to register default supported circuit
func init() {
	RegisterCircuit(AtomicQuerySigCircuitID, &AtomicQuerySigOutputs{})
}

// GetVerificationKey returns verification key for circuit
func (c *AtomicQuerySigOutputs) GetVerificationKey() VerificationKeyJSON {
	return AtomicQuerySigVerificationKey
}

type AtomicQuerySigOutputs struct {
	UserID      *core.ID
	UserState   *merkletree.Hash
	Challenge   *big.Int
	ClaimSchema core.SchemaHash
	IssuerID    *core.ID
	IssuerState *merkletree.Hash
	SlotIndex   int
	Values      []*big.Int
	Operator    int
	TimeStamp   int64
}

func (ao *AtomicQuerySigOutputs) CircuitUnmarshal(data []byte) error {
	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != 24 {
		return fmt.Errorf("invalid number of output values expected {%d} go {%d} ", 24, len(sVals))
	}

	if ao.UserID, err = IDFromStr(sVals[0]); err != nil {
		return err
	}

	if ao.UserState, err = merkletree.NewHashFromString(sVals[1]); err != nil {
		return err
	}

	var ok bool
	if ao.Challenge, ok = big.NewInt(0).SetString(sVals[2], 10); !ok {
		return fmt.Errorf("invalid challenge value: '%s'", sVals[0])
	}

	if ao.ClaimSchema, err = core.NewSchemaHashFromHex(sVals[3]); err != nil {
		return err
	}

	if ao.IssuerID, err = IDFromStr(sVals[4]); err != nil {
		return err
	}

	if ao.IssuerState, err = merkletree.NewHashFromString(sVals[5]); err != nil {
		return err
	}

	if ao.SlotIndex, err = strconv.Atoi(sVals[6]); err != nil {
		return err
	}

	// 22 doesn't include in final slice.
	for i, v := range sVals[7:22] {
		bi, ok := big.NewInt(0).SetString(v, 10)
		if !ok {
			return fmt.Errorf("invalid value in index: %d", i)
		}
		ao.Values = append(ao.Values, bi)
	}

	if ao.Operator, err = strconv.Atoi(sVals[22]); err != nil {
		return err
	}

	if ao.TimeStamp, err = strconv.ParseInt(sVals[23], 10, 64); err != nil {
		return err
	}

	return nil
}

func (ao AtomicQuerySigOutputs) GetJSONObjMap() map[string]interface{} {
	return structs.Map(ao)
}
