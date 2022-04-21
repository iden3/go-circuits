package circuits

import (
	"errors"
	"math/big"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
)

const (

	// AtomicQueryMTPPublicSignalsSchema is schema to parse json data for additional information
	AtomicQueryMTPPublicSignalsSchema PublicSchemaJSON = `{"userID":0, "userState":1,"challenge":2,"claimSchema":3, 
"issuerClaimIdenState":4,"issuerID":5,"slotIndex":6,
"value_0": 7, "value_1": 8, "value_2": 9, "value_3": 10, "value_4": 11, "value_5": 12, "value_6": 13, "value_7": 14, 
"value_9": 15, "value_10": 16, "value_11": 17, "value_12": 18, "value_13": 19, "value_14": 20, "value_15": 21,
"operator":22,"timestamp":23}`

	// AtomicQueryMTPVerificationKey is verification key to verify credentialAtomicQuery.circom
	AtomicQueryMTPVerificationKey VerificationKeyJSON = `{"protocol":"groth16","curve":"bn128","nPublic":25,"vk_alpha_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["14479172785012379639658316072639274877832189102998884319102063457129475872329","4922993222557598540025955140944466859848540671691075875800713701170315056946"],["15926808973229901278884316221590295716944895864677284472780075335569605501967","12299888517327325666751268508325237611987407797147583317555555949375472277363"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["4337701791023708634860076304258774289473301704363198981004182357286245350992","16236937179713818006416225903558633786668960270739261602073645436633421761532","1"],["13715021159035888504988328500747788814838851689501750927814633791868631593352","16373631154089525333813587120485372968080172526534199224490326901930974318469","1"],["20984244296708640517112986297731901995690508533673779732237973809391816000525","4635106361999153181613305402450734168614853088955608368945005678925478398270","1"],["9973817323388294069706344593533422374200948200830278625117420094012175157393","8846226713772141402430445539017450855871414839174177867245154992668037398082","1"],["5926122797585003946873624387333829656090189473394343796547055318454221486069","8392560817160471440310099691578268798886394955021289208980137873840302421051","1"],["12444893347365237604110859353837037455709947570689364135291174547272148650018","10222569494253026592076957505203931825722208426470754838330214383329646200156","1"],["18071509701745212297839409178844617955617588147548479212716772858444166155675","8623442330852623051374059071032944724532804860896715625926391296380205713816","1"],["10797412220167647274424031062963410905154758795874633646245233747059040697031","9974762871927456102133502602209841252657661854231959789268709463273955412392","1"],["3246718067257204035446680375512846834143103004914607248842125130890405440562","16861607085318360878993415015198513667892591414936719696028774274953273943802","1"],["5999103186166094233183249288361632175339572992484721409353358791583324338535","8341369152640817749803298176328198360597462086185206747460294916925547745783","1"],["7941378404340418531976152546586198148772985766816089579985962135966464951879","1299333388030453670148508352953547680347902044918928483741430074039842228045","1"],["5989097766178122960105830010503546621851435691203449177764277583524171786046","4241868506175466100819119478143000072599344380733527626368114146505757791725","1"],["4561320688100406635831707130041995543539763338407642858427918344531572597155","861702670394329302874852519781512108069451577779295692168222084232928027949","1"],["5476249934993035396635853572929002977922424317232136009801497539934026764737","5176398814639790852402859004847985291651654869839758825166382041285740031307","1"],["19298147637388953641933045086118517659849261459956558528543155304150021145863","16458959078376778804992116444602389098349374954630377100104006055201198759569","1"],["4089452187943506076834378942581627818957814566463726786766995339370246221433","9106100496816323791276000829702285391805875129658432495109803954352734073830","1"],["21280800106606367416672773892400085018847831390204714254558613395895837018332","12365040570712574430320070520107469032324304478933594289146554966359342271506","1"],["15682760243355137204864917674355799975183838430649856498378852449830252439377","6264685384421400312588673015871247152822033109852322323522589789040374690682","1"],["876122913245390749469149478562125679002348235803223617026371621567388160218","13035493756590673323122140236818158733857111377893437589890942275802676701913","1"],["10687398394320694581013540430152538477177748628646839821282743732142374255416","1864605083608358088106060730122521544392170042904411338343873860887138818233","1"],["20695379612199384751707680868774638888681057674961391670363629728144469501631","8824852429214237606387732147609251776273563208592891140713981480702798566305","1"],["10688899307103967179026288816711420720705572917826338210061302289474040692824","761664498037748388952994461345361187105579721339616096069739412962259656683","1"],["18237294766922563444312029707429758854262362313983247763377409982193684136713","19006921178636953970385459294800299550462045829317492459647507412338289203138","1"],["8238322229635448321067231441166239929996167350749989388459923719542555908006","2922342881913613446855700594525955275841476213119926693198058909485715476784","1"],["15730959218019792771503308266350710849149564544026259407963442172818892214579","14679166479059586432972446716877785507355580203053558525781629482000601584952","1"],["3468150003737106832427361860815867067041213451112645818076806425176448201720","6029057909705398591554580840373160108533029878396443140854094627253071280691","1"]]}`
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
	ID                 *core.ID
	AuthClaim          Claim
	AuthClaimRevStatus RevocationStatus
	Challenge          *big.Int
	Signature          *babyjub.Signature

	CurrentStateTree TreeState

	// issuerClaim
	Claim
	RevocationStatus

	// query
	Query

	TypedInputs
}

// nolint // common approach to register default supported circuit
func init() {
	RegisterCircuit(AtomicQueryMTPCircuitID, &AtomicQueryMTP{})
}

// PrepareInputs returns inputs as a map for credentialAtomicQuery.circom
func (c *AtomicQueryMTP) PrepareInputs(in TypedInputs) (map[string]interface{}, error) {

	atomicInput, ok := in.(AtomicQueryMTPInputs)
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

	return mergeMaps(claimInputs, authClaimInputs, queryInputs), nil
}

// PrepareRegularClaimInputs prepares inputs for regular claims
func (c *AtomicQueryMTP) prepareRegularClaimInputs(issuerClaim Claim, rs RevocationStatus) (map[string]interface{}, error) {

	inputs := map[string]interface{}{
		"issuerClaim": bigIntArrayToStringArray(issuerClaim.Slots),
		"issuerClaimMtp": bigIntArrayToStringArray(
			PrepareSiblings(issuerClaim.Proof.Siblings, LevelsAtomicQueryMTPCircuit)),
		"issuerClaimClaimsTreeRoot": issuerClaim.TreeState.
			ClaimsRootStr(),
		"issuerClaimRevTreeRoot": issuerClaim.TreeState.
			RevocationRootStr(),
		"issuerClaimRootsTreeRoot": issuerClaim.TreeState.
			RootOfRootsRootStr(),
		"issuerClaimIdenState": issuerClaim.TreeState.StateStr(),
		"issuerID":             issuerClaim.IssuerID.BigInt().String(),
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

	inputs["issuerClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(rs.Proof.Siblings, LevelsAtomicQueryMTPCircuit))

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
func (c *AtomicQueryMTP) prepareAuthClaimInputs(in *AtomicQueryMTPInputs) (map[string]interface{}, error) {

	if in.Signature == nil {
		return nil, errors.New("signature is null")
	}

	inputs := make(map[string]interface{})
	inputs["userID"] = in.ID.BigInt().String()
	inputs["challenge"] = in.Challenge.String()

	inputs["userAuthClaim"] = bigIntArrayToStringArray(in.AuthClaim.Slots)
	inputs["userAuthClaimMtp"] = bigIntArrayToStringArray(
		PrepareSiblings(in.AuthClaim.Proof.Siblings, LevelsAtomicQueryMTPCircuit))

	inputs["userState"] = in.CurrentStateTree.StateStr()
	inputs["userClaimsTreeRoot"] = in.CurrentStateTree.ClaimsRootStr()
	inputs["userRevTreeRoot"] = in.CurrentStateTree.RevocationRootStr()
	inputs["userRootsTreeRoot"] = in.CurrentStateTree.RootOfRootsRootStr()

	inputs["userAuthClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(in.AuthClaimRevStatus.Proof.Siblings, LevelsAtomicQueryMTPCircuit))

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

func (c *AtomicQueryMTP) prepareQueryInputs(in *AtomicQueryMTPInputs) (map[string]interface{}, error) {
	inputs := make(map[string]interface{})
	inputs["slotIndex"] = in.Query.SlotIndex
	values, err := PrepareCircuitArrayValues(in.Query.Values, ValueArraySizeAtomicQueryMTPCircuit)
	if err != nil {
		return nil, err
	}
	inputs["value"] = bigIntArrayToStringArray(values)
	inputs["operator"] = in.Query.Operator

	return inputs, nil
}

// GetVerificationKey returns verification key for circuit
func (c *AtomicQueryMTP) GetVerificationKey() VerificationKeyJSON {
	return AtomicQueryMTPVerificationKey
}

// GetPublicSignalsSchema returns schema to parse public inputs
func (c AtomicQueryMTP) GetPublicSignalsSchema() PublicSchemaJSON {
	return AtomicQueryMTPPublicSignalsSchema
}
