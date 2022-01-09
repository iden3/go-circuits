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

	// AtomicQueryPublicSignalsSchema is schema to parse json data for additional information
	AtomicQueryPublicSignalsSchema PublicSchemaJSON = `{"challenge":0,"id":1,"claimSchema":2,"slotIndex":3,"operator":4,"value":5,"timestamp":6,"queryOut":7}`

	// AtomicQueryVerificationKey is verification key to verify credentialAtomicQuery.circom
	AtomicQueryVerificationKey VerificationKeyJSON = `{"protocol":"groth16","curve":"bn128","nPublic":7,"vk_alpha_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["19567086033919739887765972107152046506397324654262888937802133595750159126717","2271111019658290993792080878537763494936011522661620971730601700839840889603"],["7500444117028187200728572339964898807961580148650112774087709437686082707237","15228841284294656083180614258452920411302535543777433887321378339841348446505"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["5895446589573788291766103122879401779227215781223012830263621242322548526378","20417212304699578075790846345368024850145927064600920875679813350450427485946","1"],["8670673608562687169427537718681529533025913759983020591543576358850830331375","3804665629455922753376380510361173712054673013413389558492657986634329609212","1"],["8991741950411765170182839895618855934425058392455855456700944139406309753441","17043449758734581877529512386555478933245160005708541184882660960617208489929","1"],["13678277025610913924679714740409613368900821949865018497333193145714150991871","14668816637700689561731877915541334738097063516936817537736814450308340568023","1"],["19912077278848742625332021286109557270568160409470333739522511303653806639674","2221214245259207668099746765698766144717327362153669622242701640690542046773","1"],["19991057585867831355176745543438486850126720734508365149893606494362836283552","1732011566897439184702277983052995638218386808745328366966787304631615937495","1"],["15167244761047502062760365452896514251833612634868779104998645395177979040706","13220947839936326121257977014353102821624397351149580656256084556140610426796","1"],["222316047448309275251553926645546700337630024925445175907772130751939404943","20573176295651738747698976200775217599539090575901937445893864989777798215351","1"]]}`
)

// LevelsAtomicQueryCircuit is number of merkle tree levels credentialAtomicQuery.circom compiled with
const LevelsAtomicQueryCircuit = 40

// AtomicQuery represents credentialAtomicQuery.circom
type AtomicQuery struct{}

// nolint // common approach to register default supported circuit
func init() {
	RegisterCircuit(AtomicQueryCircuitID, &AtomicQuery{})
}

// PrepareInputs returns inputs as a map for credentialAtomicQuery.circom
func (c *AtomicQuery) PrepareInputs(in TypedInputs) (map[string]interface{}, error) {

	atomicInput, ok := in.(AtomicQueryInputs)
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
func (c *AtomicQuery) prepareRegularClaimInputs(claim Claim, rs RevocationStatus) (map[string]interface{}, error) {

	inputs := map[string]interface{}{
		"claim": bigIntArrayToStringArray(claim.Slots),
		"claimIssuanceMtp": bigIntArrayToStringArray(
			PrepareSiblings(claim.Proof.Siblings, LevelsAtomicQueryCircuit)),
		"claimIssuanceClaimsTreeRoot": claim.TreeState.
			ClaimsRootStr(),
		"claimIssuanceRevTreeRoot": claim.TreeState.
			RevocationRootStr(),
		"claimIssuanceRootsTreeRoot": claim.TreeState.
			RootOfRootsRootStr(),
		"claimIssuanceIdenState": claim.TreeState.StateStr(),
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

	inputs["claimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(rs.Proof.Siblings, LevelsAtomicQueryCircuit))

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
func (c *AtomicQuery) prepareAuthClaimInputs(in *AtomicQueryInputs) (map[string]interface{}, error) {

	if in.Signature == nil {
		return nil, errors.New("signature is null")
	}

	inputs := make(map[string]interface{})
	inputs["id"] = in.ID.BigInt().String()
	inputs["hoIdenState"] = in.AuthClaim.TreeState.StateStr()
	inputs["challenge"] = strconv.FormatInt(in.Challenge, 10)

	inputs["authClaim"] = bigIntArrayToStringArray(in.AuthClaim.Slots)
	inputs["authClaimMtp"] = bigIntArrayToStringArray(
		PrepareSiblings(in.AuthClaim.Proof.Siblings, LevelsAtomicQueryCircuit))

	inputs["authClaimRevTreeRoot"] = in.AuthClaim.TreeState.ClaimsRoot.BigInt().String()
	inputs["authClaimRevTreeRoot"] = in.AuthClaim.TreeState.RevocationRootStr()
	inputs["authClaimRootsTreeRoot"] = in.AuthClaim.TreeState.RootOfRootsRootStr()

	inputs["authClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(in.AuthClaim.Proof.Siblings, LevelsAtomicQueryCircuit))

	if in.AuthClaim.Proof.NodeAux == nil {
		inputs["authClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		inputs["authClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		inputs["authClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(1).String() // (yes it's isOld = 1)
	} else {
		inputs["authClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(0).String() // (no it's isOld = 0)
		if in.AuthClaim.Proof.NodeAux.HIndex == nil {
			inputs["authClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["authClaimNonRevMtpAuxHi"] = in.AuthClaim.Proof.NodeAux.HIndex.BigInt().String()
		}
		if in.AuthClaim.Proof.NodeAux.HValue == nil {
			inputs["authClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["authClaimNonRevMtpAuxHv"] = in.AuthClaim.Proof.NodeAux.HValue.BigInt().String()
		}
	}

	inputs["challengeSignatureR8x"] = in.Signature.R8.X.String()
	inputs["challengeSignatureR8y"] = in.Signature.R8.Y.String()
	inputs["challengeSignatureS"] = in.Signature.S.String()

	return inputs, nil
}

func (c *AtomicQuery) prepareQueryInputs(in *AtomicQueryInputs) (map[string]interface{}, error) {
	inputs := make(map[string]interface{})
	inputs["slotIndex"] = in.Query.SlotIndex
	inputs["value"] = in.Query.Value.String()
	inputs["operator"] = in.Query.Operator

	return inputs, nil
}

// AtomicQueryInputs represents input data for kyc and kycBySignatures circuits
type AtomicQueryInputs struct {
	// auth
	ID        *core.ID
	AuthClaim Claim
	Challenge int64
	Signature *babyjub.Signature

	// claim
	Claim
	RevocationStatus

	// query
	Query

	TypedInputs
}

// GetVerificationKey returns verification key for circuit
func (c *AtomicQuery) GetVerificationKey() VerificationKeyJSON {
	return AtomicQueryVerificationKey
}

// GetPublicSignalsSchema returns schema to parse public inputs
func (c AtomicQuery) GetPublicSignalsSchema() PublicSchemaJSON {
	return AtomicQueryPublicSignalsSchema
}
