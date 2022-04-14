package circuits

import (
	"encoding/json"
	"fmt"
	"math/big"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
)

const (
	// StateTransitionVerificationKey is verification key to verify auth circuit
	StateTransitionVerificationKey VerificationKeyJSON = `{"protocol":"groth16","curve":"bn128","nPublic":3,
"vk_alpha_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["13013421765754891771005310692691340831812916477737170967264238439061371950007","17730068133177973083272121808306547358008968140724647149913786047091461584262"],["17192289157461875763016192581632448901775173085361595131803145319459949693660","4511938992569972403489478955717325699567428004796217058604461774561433395517"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["5856765512399519541027480462242148140988157031594215491715060151288404059380","6202460135402712752560615790291995563198629686687064341123045176307374429751","1"],["3547698104997057909562120202286520268471567024627674231298808172495574317468","18830005425927501982947687359433814388815419598049287066042119535580958110875","1"],["695211957568688460325854051695528957185849618184446050991937667142516722172","45705636440995849630996816823270733244007645883282775130084839778288890824","1"],["17562640942880663316675973484901590072538183129323157098134141009851408170708","15597982595003447472854223798079718346926670999630571808603803357757989957357","1"]]}`

	// IDStatePublicSignalsSchema is schema to parse json data for additional information in auth circuit
	//IDStatePublicSignalsSchema PublicSchemaJSON = `{"userID":0,"oldUserState":1,"newUserState":2}`
)

// StateTransitionMTPLevels is number of levels in MTP currently used by stateTransition circuits
const StateTransitionMTPLevels = 40

// nolint // common approach to register default supported circuit
func init() {
	RegisterCircuit(StateTransitionCircuitID, &StateTransitionOutput{})
}

// GetVerificationKey returns key to verify proof
func (s *StateTransitionOutput) GetVerificationKey() VerificationKeyJSON {
	return StateTransitionVerificationKey
}

// StateTransitionInputs ZK inputs
type StateTransitionInputs struct {
	ID *core.ID

	OldTreeState TreeState
	NewState     *merkletree.Hash

	AuthClaim                   Claim
	AuthClaimNonRevocationProof *merkletree.Proof
	Signature                   *babyjub.Signature

	TypedInputs
}

type stateTransitionInputsInternal struct {
	AuthClaim               core.Claim       `json:"authClaim"`
	AuthClaimMtp            []string         `json:"authClaimMtp"`
	AuthClaimNonRevMtp      []string         `json:"authClaimNonRevMtp"`
	AuthClaimNonRevMtpAuxHi *merkletree.Hash `json:"authClaimNonRevMtpAuxHi"`
	AuthClaimNonRevMtpAuxHv *merkletree.Hash `json:"authClaimNonRevMtpAuxHv"`
	AuthClaimNonRevMtpNoAux string           `json:"authClaimNonRevMtpNoAux"`
	UserID                  string           `json:"userID"`
	NewIdState              *merkletree.Hash `json:"newUserState"`
	OldIdState              *merkletree.Hash `json:"oldUserState"`
	ClaimsTreeRoot          *merkletree.Hash `json:"claimsTreeRoot"`
	RevTreeRoot             *merkletree.Hash `json:"revTreeRoot"`
	RootsTreeRoot           *merkletree.Hash `json:"rootsTreeRoot"`
	SignatureR8X            string           `json:"signatureR8x"`
	SignatureR8Y            string           `json:"signatureR8y"`
	SignatureS              string           `json:"signatureS"`
}

func (c StateTransitionInputs) CircuitMarshal() ([]byte, error) {

	s := stateTransitionInputsInternal{
		AuthClaim:          *c.AuthClaim.Claim,
		AuthClaimMtp:       PrepareSiblingsStr(c.AuthClaim.AProof.AllSiblings(), StateTransitionMTPLevels),
		AuthClaimNonRevMtp: PrepareSiblingsStr(c.AuthClaimNonRevocationProof.AllSiblings(), StateTransitionMTPLevels),
		UserID:             c.ID.BigInt().String(),
		NewIdState:         c.NewState,
		ClaimsTreeRoot:     c.OldTreeState.ClaimsRoot,
		OldIdState:         c.OldTreeState.State,
		RevTreeRoot:        c.OldTreeState.RevocationRoot,
		RootsTreeRoot:      c.OldTreeState.RootOfRoots,
		SignatureR8X:       c.Signature.R8.X.String(),
		SignatureR8Y:       c.Signature.R8.Y.String(),
		SignatureS:         c.Signature.S.String(),
	}

	if c.AuthClaimNonRevocationProof.NodeAux == nil {
		s.AuthClaimNonRevMtpAuxHi = &merkletree.HashZero
		s.AuthClaimNonRevMtpAuxHv = &merkletree.HashZero
		s.AuthClaimNonRevMtpNoAux = "1"
	} else {
		s.AuthClaimNonRevMtpAuxHi = c.AuthClaimNonRevocationProof.NodeAux.Key
		s.AuthClaimNonRevMtpAuxHv = c.AuthClaimNonRevocationProof.NodeAux.Value
		s.AuthClaimNonRevMtpNoAux = "0"
	}

	return json.Marshal(s)
}

// StateTransitionOutput `{"userID":0,"oldUserState":1,"newUserState":2}`
type StateTransitionOutput struct {
	UserID       *core.ID         `json:"userID"`
	OldUserState *merkletree.Hash `json:"oldUserState"`
	NewUserState *merkletree.Hash `json:"newUserState"`
}

func (c *StateTransitionOutput) PrepareInputs(i TypedInputs) (map[string]interface{}, error) {
	//TODO implement me
	panic("implement me")
}

func (c *StateTransitionOutput) GetPublicSignalsSchema() PublicSchemaJSON {
	//TODO implement me
	panic("implement me")
}

//func (s *StateTransitionOutput) JSONObj() map[string]interface {
//	StateTransitionOutput
//}

func (s *StateTransitionOutput) CircuitUnmarshal(data []byte) error {
	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != 3 {
		return fmt.Errorf("invalid number of output values expected {%d} go {%d} ", 3, len(sVals))
	}

	if s.UserID, err = IDFromStr(sVals[0]); err != nil {
		return err
	}
	if s.OldUserState, err = merkletree.NewHashFromString(sVals[1]); err != nil {
		return err
	}
	if s.NewUserState, err = merkletree.NewHashFromString(sVals[2]); err != nil {
		return err
	}
	return nil
}

func IDFromStr(s string) (*core.ID, error) {
	strID, b := new(big.Int).SetString(s, 10)
	if b == false {
		return nil, fmt.Errorf("can not convert {%s} to ID", s)
	}
	id, err := core.IDFromInt(strID)
	if err != nil {
		return nil, err
	}

	return &id, nil
}
