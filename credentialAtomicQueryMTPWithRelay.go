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
	// AtomicQueryMTPWithRelayVerificationKey is verification key to verify credentialAtomicQuery.circom
	AtomicQueryMTPWithRelayVerificationKey VerificationKeyJSON = `{"protocol":"groth16","curve":"bn128","nPublic":24,"vk_alpha_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["6278484784417131357610619566489765072905563067236434324871089044431100506174","16798206068020529493605510857259259682117344912379167912101054494433638691714"],["3714161280986964248682314882913067749904563493958267836148199639437245873893","6065681925074325096112697482817309689312956026391365025651593616095414493747"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["18565358146943129805005934863971831390201535690832864371249695080084959963999","2486106559102242235729389614678033531122844496625393193177595381608692272532","1"],["14429630295374388421046276607594659250144894127522098836619505251365743093879","10235105741724152716569968563337400952493644308988573851213872655449151219253","1"],["11069857379126380286062349812886818693395114885823935107479366572827690198828","10701089096069639780264998482049481304146255809078458357280159926848343948005","1"],["3898452169757627670991015800984885685548494168614072567829254899715863084101","7228782272458273262222371639678692401830584658256147439163704461508282519280","1"],["21035376059256016862298015155869999862274147314277884762256914707190239226513","1743741924836187398789743795355437493953803963816409630208506966833131512396","1"],["4533945492453231644286024178699254471658210022695039441468151377292501366563","4846814568445170478220717358369315680293827600899009789495426946412239366789","1"],["694175713551050920500239665104912318176292555989941280687678002314202334930","458296016920663249987092618801268009938546893407850516911717895565762771748","1"],["18258373167682869683428826594698431306404588902364464359563692076404853396849","13235184162623942523085847624651165716856761575007622403544973016785150847100","1"],["18989912718156135066623331391907565549031410251204496598354592782340020457954","6625797359025068361758298766418088486800292536617295257529614628296293112091","1"],["939272524268426508435024843436916318855964058088523192692811660508394454917","16814500213558465935771097529305492583761907672726167241036820682386214245763","1"],["12658399037715824829540040256882379309601185340565664440364779925307008537122","11142996794034794022698484802963738451727637101386075453387964957614358081262","1"],["1421408269856658682630268091208365583217351182902846171279123955522228311126","7581148818685866651644303291185095889722102688346350129361895549820861520625","1"],["20179563967926250798787630320536154013380688405147086534045110920928805483636","15381392029315114105579793694808635636260230806590141019696748723025080287525","1"],["2813471089923933726801792193777292775032877555926765248388312601897379094416","19802030916329103432576992311760688208334983118892724932927552557554897442224","1"],["5095664018570052030708625904486487118411718205731421943960578350578439484484","8888978932289149222835721232600588075597587801010999088494690861582057082174","1"],["20127174763715418966516367832431042056171250674404819084432727810972121282048","16136541751029276094583515944530588088654940220661660641555503746457425939610","1"],["13389361250052186200918297934864238256746199671738047797020042303572971630787","18392464728346781957909131747776605155201884883655087108937234547101015801393","1"],["10884764282239124164038370704292036513430850984299568398273141354563871892902","19681966425513546568667832386733355555941383582794811819483488960968829744409","1"],["14263942956920671627375568337781668893085349770408065774051903924795334400864","13458429030014248465690080742415501251070899560365683446219398921490880617574","1"],["3459510615231633628844343622876170221005125053068502978152683527792260662365","12300716360139326475191318435456882143595352388375139309371502999997652135996","1"],["2284124144238775365209747793235316276074478073285998301707721402804010338804","5269312874924133974619127377977809697509359641471573610906557880270044403425","1"],["20138685913567764936720312215496084906292339277068732711582265678557973040075","3642443504288430504669311419982882216249000875944845716713241705986197791268","1"],["21087566483374695169409038186841225179844815064880113892588025508981620537500","14435980116984911410121318252590224861413392394857138127184213144910219304160","1"],["5512974253961586242049755435440895833313644846088888163068581237321034730801","4660625188975080581358448715647081476890078270202856220593231478180547385608","1"],["15127631479239981182817612106951596579743184294592656628274718914831541613055","11106188644488581129772595425155036235520962553338962974867223606453229907116","1"]]}`
)

// LevelsAtomicQueryMTPWithRelayCircuit is number of merkle tree levels credentialAtomicQuery.circom compiled with
const LevelsAtomicQueryMTPWithRelayCircuit = 40

// ValueArraySizeAtomicQueryMTPWithRelayCircuit size of value array
const ValueArraySizeAtomicQueryMTPWithRelayCircuit = 16

type AtomicQueryMTPWithRelay struct{}

// AtomicQueryMTPWithRelayInputs represents input data for kyc and kycBySignatures circuits
type AtomicQueryMTPWithRelayInputs struct {
	// auth
	ID        *core.ID
	AuthClaim Claim
	Challenge *big.Int
	Signature *babyjub.Signature

	// relay
	UserStateInRelayClaim Claim

	// claim
	Claim

	CurrentTimeStamp int64
	Schema           core.SchemaHash

	// query
	Query

	CircuitMarshaller
}

type atomicQueryMTPWithRelayCircuitInputs struct {
	UserAuthClaim               *core.Claim      `json:"userAuthClaim"`
	UserAuthClaimMtp            []string         `json:"userAuthClaimMtp"`
	UserAuthClaimNonRevMtp      []string         `json:"userAuthClaimNonRevMtp"`
	UserAuthClaimNonRevMtpAuxHi *merkletree.Hash `json:"userAuthClaimNonRevMtpAuxHi"`
	UserAuthClaimNonRevMtpAuxHv *merkletree.Hash `json:"userAuthClaimNonRevMtpAuxHv"`
	UserAuthClaimNonRevMtpNoAux string           `json:"userAuthClaimNonRevMtpNoAux"`
	UserClaimsTreeRoot          *merkletree.Hash `json:"userClaimsTreeRoot"`
	//UserState                   *merkletree.Hash `json:"userState"`
	UserRevTreeRoot   *merkletree.Hash `json:"userRevTreeRoot"`
	UserRootsTreeRoot *merkletree.Hash `json:"userRootsTreeRoot"`
	UserID            string           `json:"userID"`

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

	RelayProofValidClaimsTreeRoot *merkletree.Hash `json:"relayProofValidClaimsTreeRoot"`
	RelayProofValidRevTreeRoot    *merkletree.Hash `json:"relayProofValidRevTreeRoot"`
	RelayProofValidRootsTreeRoot  *merkletree.Hash `json:"relayProofValidRootsTreeRoot"`
	RelayState                    *merkletree.Hash `json:"relayState"`
	UserStateInRelayClaim         *core.Claim      `json:"userStateInRelayClaim"`
	UserStateInRelayClaimMtp      []string         `json:"userStateInRelayClaimMtp"`
}

func (a AtomicQueryMTPWithRelayInputs) CircuitMarshal() ([]byte, error) {

	s := atomicQueryMTPWithRelayCircuitInputs{
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
		//UserState:          a.AuthClaim.TreeState.State,
		UserRevTreeRoot:   a.AuthClaim.TreeState.RevocationRoot,
		UserRootsTreeRoot: a.AuthClaim.TreeState.RootOfRoots,
		UserID:            a.ID.BigInt().String(),
		IssuerID:          a.IssuerID.BigInt().String(),
		Operator:          a.Operator,
		SlotIndex:         a.SlotIndex,
		Timestamp:         a.CurrentTimeStamp,

		RelayProofValidClaimsTreeRoot: a.UserStateInRelayClaim.TreeState.ClaimsRoot,
		RelayProofValidRevTreeRoot:    a.UserStateInRelayClaim.TreeState.RevocationRoot,
		RelayProofValidRootsTreeRoot:  a.UserStateInRelayClaim.TreeState.RootOfRoots,
		RelayState:                    a.UserStateInRelayClaim.TreeState.State,
		UserStateInRelayClaim:         a.UserStateInRelayClaim.Claim,
		UserStateInRelayClaimMtp: bigIntArrayToStringArray(
			PrepareSiblings(a.UserStateInRelayClaim.Proof.AllSiblings(), LevelsAtomicQueryMTPWithRelayCircuit)),
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
	RegisterCircuit(AtomicQueryMTPWithRelayCircuitID, &AtomicQueryMTPWithRelayOutputs{})
}

// GetVerificationKey returns verification key for circuit
func (ao *AtomicQueryMTPWithRelayOutputs) GetVerificationKey() VerificationKeyJSON {
	return AtomicQueryMTPWithRelayVerificationKey
}

type AtomicQueryMTPWithRelayOutputs struct {
	UserID      *core.ID
	RelayState  *merkletree.Hash
	Challenge   *big.Int
	ClaimSchema core.SchemaHash
	SlotIndex   int
	Operator    int
	Value       *big.Int
	TimeStamp   int64
	IssuerID    *core.ID
}

func (ao *AtomicQueryMTPWithRelayOutputs) CircuitUnmarshal(data []byte) error {
	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != 9 {
		return fmt.Errorf("invalid number of output values expected {%d} go {%d} ", 9, len(sVals))
	}

	if ao.UserID, err = IDFromStr(sVals[0]); err != nil {
		return err
	}

	if ao.RelayState, err = merkletree.NewHashFromString(sVals[1]); err != nil {
		return err
	}

	var ok bool
	if ao.Challenge, ok = big.NewInt(0).SetString(sVals[2], 10); !ok {
		return fmt.Errorf("invalid challenge value: '%s'", sVals[0])
	}

	if ao.ClaimSchema, err = core.NewSchemaHashFromHex(sVals[3]); err != nil {
		return err
	}

	if ao.SlotIndex, err = strconv.Atoi(sVals[4]); err != nil {
		return err
	}

	if ao.Operator, err = strconv.Atoi(sVals[5]); err != nil {
		return err
	}

	if ao.Value, ok = big.NewInt(0).SetString(sVals[6], 10); !ok {
		return fmt.Errorf("invalid challenge value: '%s'", sVals[0])
	}

	if ao.TimeStamp, err = strconv.ParseInt(sVals[7], 10, 64); err != nil {
		return err
	}

	if ao.IssuerID, err = IDFromStr(sVals[8]); err != nil {
		return err
	}

	return nil
}

func (ao AtomicQueryMTPWithRelayOutputs) GetJSONObjMap() map[string]interface{} {
	return structs.Map(ao)
}
