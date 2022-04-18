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
	ID        *core.ID
	AuthClaim Claim
	Challenge *big.Int
	Signature *babyjub.Signature

	//CurrentStateTree TreeState

	// issuerClaim
	Claim

	Schema           core.SchemaHash
	CurrentTimeStamp int64

	// query
	Query

	CircuitMarshaller
}

type atomicQueryMTPCircuitInputs struct {
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
	IssuerClaimClaimsTreeRoot       *merkletree.Hash `json:"issuerClaimClaimsTreeRoot"`
	IssuerClaimIdenState            *merkletree.Hash `json:"issuerClaimIdenState"`
	IssuerClaimMtp                  []string         `json:"issuerClaimMtp"`
	IssuerClaimRevTreeRoot          *merkletree.Hash `json:"issuerClaimRevTreeRoot"`
	IssuerClaimRootsTreeRoot        *merkletree.Hash `json:"issuerClaimRootsTreeRoot"`
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
}

func (a AtomicQueryMTPInputs) CircuitMarshal() ([]byte, error) {

	s := atomicQueryMTPCircuitInputs{
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
		IssuerClaimClaimsTreeRoot:       a.Claim.TreeState.ClaimsRoot,
		IssuerClaimIdenState:            a.Claim.TreeState.State,
		IssuerClaimMtp:                  PrepareSiblingsStr(a.Claim.Proof.AllSiblings(), LevelsAtomicQueryMTPCircuit),
		IssuerClaimRevTreeRoot:          a.Claim.TreeState.RevocationRoot,
		IssuerClaimRootsTreeRoot:        a.Claim.TreeState.RootOfRoots,
		IssuerClaimNonRevClaimsTreeRoot: a.Claim.NonRevProof.TreeState.ClaimsRoot,
		IssuerClaimNonRevRevTreeRoot:    a.Claim.NonRevProof.TreeState.RevocationRoot,
		IssuerClaimNonRevRootsTreeRoot:  a.Claim.NonRevProof.TreeState.RootOfRoots,
		IssuerClaimNonRevState:          a.Claim.NonRevProof.TreeState.State,
		IssuerClaimNonRevMtp: PrepareSiblingsStr(a.Claim.NonRevProof.Proof.AllSiblings(),
			LevelsAtomicQueryMTPCircuit),
		ClaimSchema:        new(big.Int).SetBytes(a.Schema[:]).String(),
		UserClaimsTreeRoot: a.AuthClaim.TreeState.ClaimsRoot,
		UserState:          a.AuthClaim.TreeState.State,
		UserRevTreeRoot:    a.AuthClaim.TreeState.RevocationRoot,
		UserRootsTreeRoot:  a.AuthClaim.TreeState.RootOfRoots,
		UserID:             a.ID.BigInt().String(),
		IssuerID:           a.IssuerID.BigInt().String(),
		Operator:           a.Operator,
		SlotIndex:          a.SlotIndex,
		Timestamp:          a.CurrentTimeStamp,
	}

	values, err := PrepareCircuitArrayValues(a.Values, ValueArraySizeAtomicQueryMTPCircuit)
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
	RegisterCircuit(AtomicQueryMTPCircuitID, &AtomicQueryMTPOutputs{})
}

// GetVerificationKey returns verification key for circuit
func (ao *AtomicQueryMTPOutputs) GetVerificationKey() VerificationKeyJSON {
	return AtomicQueryMTPVerificationKey
}

type AtomicQueryMTPOutputs struct {
	UserID               *core.ID
	UserState            *merkletree.Hash
	Challenge            *big.Int
	ClaimSchema          core.SchemaHash
	IssuerClaimIdenState *merkletree.Hash
	IssuerID             *core.ID
	SlotIndex            int
	Values               []*big.Int
	Operator             int
	Timestamp            int64
}

func (ao *AtomicQueryMTPOutputs) CircuitUnmarshal(data []byte) error {
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

	if ao.IssuerClaimIdenState, err = merkletree.NewHashFromString(sVals[4]); err != nil {
		return err
	}

	if ao.IssuerID, err = IDFromStr(sVals[5]); err != nil {
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

	if ao.Timestamp, err = strconv.ParseInt(sVals[23], 10, 64); err != nil {
		return err
	}

	return nil
}

func (ao AtomicQueryMTPOutputs) GetJSONObjMap() map[string]interface{} {
	return structs.Map(ao)
}
