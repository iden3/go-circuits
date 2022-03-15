package circuits

import (
	"errors"
	"math/big"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
)

const (
	// AtomicQueryMTPWithRelayPublicSignalsSchema is schema to parse json data for additional information
	AtomicQueryMTPWithRelayPublicSignalsSchema PublicSchemaJSON = `{"user_identifier":0, "relayState":1,"challenge":2,"claimSchema":3,"slotIndex":4,"operator":5,"value":6,"timestamp":7, "issuerID":8}`

	// AtomicQueryMTPWithRelayVerificationKey is verification key to verify credentialAtomicQuery.circom
	AtomicQueryMTPWithRelayVerificationKey VerificationKeyJSON = `{"protocol":"groth16","curve":"bn128","nPublic":24,"vk_alfa_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["17662278141774853259783427226048603970573291195029845510969279580971108177752","15363444356648048755959142349570350524012194757556443089256929541114131268561"],["2627159640754381174593852762500213785675942863564128160592276403377574316810","6265056773515487034113004082984071151696083796220684491015697162801152537642"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["12440477068587338792852240673862206417263378800293314803427851358511740374194","17141206062904886869830561593423779172920418323091840506385746864124765394746","1"],["5746162471453273783809873910747149665595201970969365431624734176953486220049","15913146658031120076622905511582363082239243345098390999926911705457839351991","1"],["7870502500836855549670282300993219592404055681842904367871881493079456194722","15152979758780425447727233579877267681562542000680173848348138648585597421997","1"],["10600932212124283631155281227984176271174592123880729096307255449912907469589","17541757774482200192907967186806837718645731729190877631964511417916364834981","1"],["7265081740989016879236427969451037717344884381824626217724433464299422502113","17258699849497821736345434067387623893955135310246042740226719003155246456597","1"],["18523014519605816658494703129647298378468156290875217843133323179750414630231","12680768988616281302209565560795248759871980854290298340387345105549534023650","1"],["262662477068435406486426625484154456235019065520725094403825294721221251400","11284262843031066211813922294209540975211894248365092568566323371461646532839","1"],["11079657783753193230705392705354621116816727265850821275138889581344006952013","2810216968439765011805022313550651229877627560533173953238141653317463782949","1"],["9223595699905107862323593944763455270298310418726121742904582596290385433272","9520911079557483359256044915383663087282532566550161871205604799701616859307","1"],["2453637300933156151913471388005432290205475823749762795966502787713330919397","17626501447631555438471094121056146422546587207169941153578757579354519372386","1"],["20299296354547215816196515877470479939681863731126999929203505010560176743509","9281533250776611056122569213915744630645754816770048518958283772073472140960","1"],["10773220848072279657847417188973800377577406916523012303257471597902598943364","2162423021911198810139295183957485939327191234705284934267078441357391730513","1"],["11687316304710163930858174108276068508137077645171138684536577637819989177914","15802373913271345112172055673147074084248578207789928223402043152729761570662","1"],["14717865026736016145790107562972654989410323191188701625351228322129478232912","3379289964991601465224086175304724078336771028002388033931418088919646602167","1"],["3630103491436973549481486644476655795401187165578612495252654925341323447962","8698796443113080903944904244325470517170342348357668147308491158363832246881","1"],["7855908251223775013950566123433089602218003936742396081340310972297676542013","3812590038566808271947062282337716230137718665867339427359410659000480002343","1"],["18545492885942215737049004832088609634162633625911715249314853234192493684260","8936508304395979387994034905877387357848893088470013100161442079733002939122","1"],["20149428730720590202466191442107273682916377416761409639058819805842696845373","7658214767865561210921080823992466471595740913840412059889335603669688907978","1"],["17037467206547780827070608838819943193534824799961802451448725828167665594078","4053226627914797325150831941352066844415581991552704063196751278281850600387","1"],["4457027852797565531279126339365134708821461253736003228402622109684461442811","19025023227846886409179641256380543650495793721680424821244045106368807774006","1"],["16813318004569152748974305228546505264674252175673105433595486174220700447029","10654663669547620902845113369766779709965651900301120045027965542585834992979","1"],["9621536826633197929192964076463659571647817164250003769164232307600646461457","15262638283246369354482154216236494010247112459648221664943202107384057089967","1"],["3762502864025223875026796995862923691262575221773580080744695406831357254867","18338878589910975799001256302982038789810866806656365674516842659860718869148","1"],["11225180794309367441911210304921481439763985684697274090921414453445436759607","6631328651185425505979432278127892501709085972586711359675373551153501950608","1"],["16191972669592001709226032157895075073341464703091116224729793510015677586847","20499249672412562122489620652535455791259413675143117920437672873335373879284","1"]]}`
)

// LevelsAtomicQueryMTPWithRelayCircuit is number of merkle tree levels credentialAtomicQuery.circom compiled with
const LevelsAtomicQueryMTPWithRelayCircuit = 40

// ValueArraySizeAtomicQueryMTPWithRelayCircuit size of value array
const ValueArraySizeAtomicQueryMTPWithRelayCircuit = 16

type AtomicQueryMTPWithRelay struct{}

// AtomicQueryMTPWithRelayInputs represents input data for kyc and kycBySignatures circuits
type AtomicQueryMTPWithRelayInputs struct {
	// auth
	ID                 *core.ID
	AuthClaim          Claim
	AuthClaimRevStatus RevocationStatus
	Challenge          *big.Int
	Signature          *babyjub.Signature

	CurrentStateTree TreeState

	// relay
	UserStateInRelayClaim Claim

	// claim
	Claim
	RevocationStatus

	// query
	Query

	TypedInputs
}

// nolint // common approach to register default supported circuit
func init() {
	RegisterCircuit(AtomicQueryMTPWithRelayCircuitID, &AtomicQueryMTPWithRelay{})
}

func (c *AtomicQueryMTPWithRelay) PrepareInputs(in TypedInputs) (map[string]interface{}, error) {
	atomicInput, ok := in.(AtomicQueryMTPWithRelayInputs)
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

	relayInputs, err := c.prepareRelayClaimInputs(atomicInput.UserStateInRelayClaim)
	if err != nil {
		return nil, err
	}

	return mergeMaps(claimInputs, authClaimInputs, queryInputs, relayInputs), nil
}

// PrepareRegularClaimInputs prepares inputs for regular claims
func (c *AtomicQueryMTPWithRelay) prepareRegularClaimInputs(claim Claim, rs RevocationStatus) (map[string]interface{}, error) {

	inputs := map[string]interface{}{
		"claim": bigIntArrayToStringArray(claim.Slots),
		"claimIssuanceMtp": bigIntArrayToStringArray(
			PrepareSiblings(claim.Proof.Siblings, LevelsAtomicQueryMTPWithRelayCircuit)),
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

	inputs["claimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(rs.Proof.Siblings, LevelsAtomicQueryMTPWithRelayCircuit))

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
func (c *AtomicQueryMTPWithRelay) prepareAuthClaimInputs(in *AtomicQueryMTPWithRelayInputs) (map[string]interface{}, error) {

	if in.Signature == nil {
		return nil, errors.New("signature is null")
	}

	inputs := make(map[string]interface{})
	inputs["userID"] = in.ID.BigInt().String()
	inputs["challenge"] = in.Challenge.String()

	inputs["authClaim"] = bigIntArrayToStringArray(in.AuthClaim.Slots)
	inputs["authClaimMtp"] = bigIntArrayToStringArray(
		PrepareSiblings(in.AuthClaim.Proof.Siblings, LevelsAtomicQueryMTPWithRelayCircuit))

	// Note: we don't setup inputs user state, e.g. ["hoIdenState"] = in.CurrentStateTree.StateStr() here
	// as there is no need for it with relay
	inputs["userClaimsTreeRoot"] = in.CurrentStateTree.ClaimsRootStr()
	inputs["userRevTreeRoot"] = in.CurrentStateTree.RevocationRootStr()
	inputs["userRootsTreeRoot"] = in.CurrentStateTree.RootOfRootsRootStr()

	inputs["authClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(in.AuthClaimRevStatus.Proof.Siblings, LevelsAtomicQueryMTPWithRelayCircuit))

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

func (c *AtomicQueryMTPWithRelay) prepareQueryInputs(in *AtomicQueryMTPWithRelayInputs) (map[string]interface{}, error) {
	inputs := make(map[string]interface{})
	inputs["slotIndex"] = in.Query.SlotIndex
	values, err := PrepareCircuitArrayValues(in.Query.Values, ValueArraySizeAtomicQueryMTPWithRelayCircuit)
	if err != nil {
		return nil, err
	}
	inputs["value"] = bigIntArrayToStringArray(values)
	inputs["operator"] = in.Query.Operator

	return inputs, nil
}

// Prepares inputs for the claim that user state is in relay state
func (c *AtomicQueryMTPWithRelay) prepareRelayClaimInputs(claim Claim) (map[string]interface{}, error) {
	inputs := map[string]interface{}{
		"relayState": claim.TreeState.StateStr(),
		"userStateInRelayClaimMtp": bigIntArrayToStringArray(
			PrepareSiblings(claim.Proof.Siblings, LevelsAtomicQueryMTPWithRelayCircuit)),
		"userStateInRelayClaim":         bigIntArrayToStringArray(claim.Slots),
		"relayProofValidClaimsTreeRoot": claim.TreeState.ClaimsRootStr(),
		"relayProofValidRevTreeRoot":    claim.TreeState.RevocationRootStr(),
		"relayProofValidRootsTreeRoot":  claim.TreeState.RootOfRootsRootStr(),
	}
	return inputs, nil
}

// GetVerificationKey returns verification key for circuit
func (c *AtomicQueryMTPWithRelay) GetVerificationKey() VerificationKeyJSON {
	return AtomicQueryMTPWithRelayVerificationKey
}

// GetPublicSignalsSchema returns schema to parse public inputs
func (c AtomicQueryMTPWithRelay) GetPublicSignalsSchema() PublicSchemaJSON {
	return AtomicQueryMTPWithRelayPublicSignalsSchema
}
