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

	// AtomicQuerySigPublicSignalsSchema is schema to parse json data for additional information
	AtomicQuerySigPublicSignalsSchema PublicSchemaJSON = `{"user_identifier": 0, "hoIdenState": 1, "challenge": 2, "claimSchema": 3, "issuerID": 4, "slotIndex":5, "value_0": 6, "value_1": 7, "value_2": 8, "value_3": 9, "value_4": 10, "value_5": 11, "value_6": 12, "value_7": 13, "value_9": 14, "value_10": 15, "value_11": 16, "value_12": 17, "value_13": 18, "value_14": 19, "value_15": 20, "operator": 21, "timestamp": 22}`

	// AtomicQuerySigVerificationKey is verification key to verify credentialAttrQuerySig.circom
	AtomicQuerySigVerificationKey VerificationKeyJSON = `{"protocol":"groth16","curve":"bn128","nPublic":24,"vk_alfa_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["11399111975237339421911389363486158749989583620999255399949756342349967437772","18697193601469467584681945334104209780760369415242147648064077108262619071100"],["16033896622303703727936011875314554396642967084106673561618747274675283545735","16010763606498518225780181260910349784986351635398268828982364495843785538129"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["9056879998269897110371040375505468838982983209796685277007510305400075177012","19789845017300106440126278764635460044955090504006316759160341950439026845656","1"],["18565047771903659153084970115443706304427092001735932895479987211775691221799","1890380070267698819780933683916218825658694779865483245184857637737925572517","1"],["780174388378650871177855968865080905147010409957331853547992473136475925082","19345076338787764261593414865124630011860468307275361219728075189085316906779","1"],["5839453759380448434084840785397386469252292876551596693377773260707643997677","19191052974828499829227258402089894454509644208712778416359150904826198484017","1"],["6930446571407405004115992447277808044605054218705389307783402643458912458491","5237719106611425934344022276838267715438070999560740067171375974201442873442","1"],["18828755602729931743996744736808797329881222056309939372559568480401278441674","20495364727031551730553719956843279309071839313920241802317821058111083742834","1"],["7308281746849360718723586117023693519130161155531100694673426496082356610046","15970860799233040834475463346610629068171255461970235729839160128534286137939","1"],["9991474660965645175242856149108377230060790201564835794578284243688169313161","17297550133387899179513647757341129822206840698671791228391246679934425573029","1"],["10616790184078061174219764499975812901153620230023545510312806573781846310331","16072960747885396193057378946173549381642057403841073750517270520284165583724","1"],["20545219743576738343175039045127564214158309196859260495160224874274710134401","4156905293884816202447421070633321378486696454554300323083700899739926009837","1"],["12640235718835889962409908136463855375297323581750167058571263178136423140834","5157967189847030810954546898913223026695166523252112701026663392505951488130","1"],["6834921546921566108020373074785230677345082729248013213392375433271394564557","6247156505216421032559972894786155352299315448244777787995436406517176691351","1"],["5644865152021936534877738355894221633943140875233737057703252031211907148806","10093979045497329383167464489755645395117492403389191014370153745691651474448","1"],["15912368668523756863186785393707659840677189521438799928115675637011100646050","5376854011595303453437932301607003475150652026823205634188740721098717618804","1"],["19029197485258694254454466010715321097582545220198825016863497057946893554217","11409546854719401469348694452903983436295030818551391025896067703378970305","1"],["18821466665777954012079044920057307429023469859374697989305787732856252528944","12633789321304875622704416542532744423367359322213888378058956310901394022412","1"],["18517649378306093401638485837114186903929803442550799430122926576825373501356","18685205890271769951798277815086296471244303529302978568009808182936441401330","1"],["431912700371815230406775436171217189530718721432780608544199784314840132488","6471997929796790557670736643778032131459741975903392610549592375165277202031","1"],["3464294818520896985213111283375840981041634754223403497371410899608909216555","9961247147736106317645686134907315225799068477653136509665049289228752545528","1"],["2266745794766153000923881350382148577235427212398314044823116818478304269769","13146617737633813523074008503437076832459909028156438060897994008299116262735","1"],["6303975887724177388977423629647890323392317881918772604348927750539120166820","5469119505120999123742591303593547144292925453379630598521884883763906489183","1"],["20169429769272841652921111474716790795636362566916307056080860406986984427206","12203552225753470105463982301654162095011358624710935591631854955130844381549","1"],["15257637921713001889684673611904453815349565533177249315305355138101478085793","6747669824027797198518915574132534374231056582501078957338331631152096929610","1"],["20154441542584780362651832401191304399456182065447976646723752394881805651456","18999038600752369338158954323825392697891688742567006649557037800178724212690","1"],["15951984819922555138440535985879859130575934567343653706847738678446418419029","1040323238746910513727426681093435686682997944934832058438221379656481226131","1"]]}`
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
	Challenge          int64
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
	inputs["challenge"] = strconv.FormatInt(in.Challenge, 10)

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
