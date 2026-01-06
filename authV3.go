package circuits

import (
	"encoding/json"
	"fmt"
	"math/big"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
)

// AuthV3Inputs type represent authV3.circom/authV3-8-32.circom inputs
type AuthV3Inputs struct {
	BaseConfig `json:"-"`

	GenesisID    *core.ID `json:"genesisID"`
	ProfileNonce *big.Int `json:"profileNonce"`

	AuthClaim *core.Claim `json:"authClaim"`

	AuthClaimIncMtp    *merkletree.Proof `json:"authClaimIncMtp"`
	AuthClaimNonRevMtp *merkletree.Proof `json:"authClaimNonRevMtp"`
	TreeState          TreeState         `json:"treeState"`

	GISTProof GISTProof `json:"gistProof"`

	Signature *babyjub.Signature `json:"signature"`
	Challenge *big.Int           `json:"challenge"`
}

func (a AuthV3Inputs) Validate() error {

	if a.GenesisID == nil {
		return errors.New(ErrorEmptyID)
	}

	if a.AuthClaimIncMtp == nil {
		return errors.New(ErrorEmptyAuthClaimProof)
	}

	if a.AuthClaimNonRevMtp == nil {
		return errors.New(ErrorEmptyAuthClaimNonRevProof)
	}

	if a.GISTProof.Proof == nil {
		return errors.New(ErrorEmptyGISTProof)
	}

	if a.Signature == nil {
		return errors.New(ErrorEmptyChallengeSignature)
	}

	if a.Challenge == nil {
		return errors.New(ErrorEmptyChallenge)
	}

	return nil
}

// InputsMarshal returns Circom private inputs for auth.circom
func (a AuthV3Inputs) InputsMarshal() ([]byte, error) {

	if err := a.Validate(); err != nil {
		return nil, err
	}

	s := authCircuitInputs{
		GenesisID:    a.GenesisID.BigInt().String(),
		ProfileNonce: a.ProfileNonce.String(),
		AuthClaim:    a.AuthClaim,
		AuthClaimMtp: merkletree.CircomSiblingsFromSiblings(a.AuthClaimIncMtp.AllSiblings(),
			a.GetMTLevel()-1),
		AuthClaimNonRevMtp: merkletree.CircomSiblingsFromSiblings(a.AuthClaimNonRevMtp.AllSiblings(),
			a.GetMTLevel()-1),
		Challenge:             a.Challenge.String(),
		ChallengeSignatureR8X: a.Signature.R8.X.String(),
		ChallengeSignatureR8Y: a.Signature.R8.Y.String(),
		ChallengeSignatureS:   a.Signature.S.String(),
		ClaimsTreeRoot:        a.TreeState.ClaimsRoot,
		RevTreeRoot:           a.TreeState.RevocationRoot,
		RootsTreeRoot:         a.TreeState.RootOfRoots,
		State:                 a.TreeState.State,
		GISTRoot:              a.GISTProof.Root,
		GISTMtp: merkletree.CircomSiblingsFromSiblings(a.GISTProof.Proof.AllSiblings(),
			a.GetMTLevelOnChain()-1),
	}

	nodeAuxAuth := GetNodeAuxValue(a.AuthClaimNonRevMtp)
	s.AuthClaimNonRevMtpAuxHi = nodeAuxAuth.key
	s.AuthClaimNonRevMtpAuxHv = nodeAuxAuth.value
	s.AuthClaimNonRevMtpNoAux = nodeAuxAuth.noAux

	gistNodeAux := GetNodeAuxValue(a.GISTProof.Proof)
	s.GISTMtpAuxHi = gistNodeAux.key
	s.GISTMtpAuxHv = gistNodeAux.value
	s.GISTMtpNoAux = gistNodeAux.noAux

	return json.Marshal(s)
}

// GetPublicStatesInfo returns states and gists information,
// implements PublicStatesInfoProvider interface
func (a AuthV3Inputs) GetPublicStatesInfo() (StatesInfo, error) {

	if err := a.Validate(); err != nil {
		return StatesInfo{}, err
	}

	userID, err := core.ProfileID(*a.GenesisID, a.ProfileNonce)
	if err != nil {
		return StatesInfo{}, err
	}
	return StatesInfo{
		States: []State{},
		Gists: []Gist{
			{
				ID:   userID,
				Root: *a.GISTProof.Root,
			},
		},
	}, nil
}

type authV3JsonAlias AuthV3Inputs
type authV3Json struct {
	*authV3JsonAlias
	ProfileNonce *jsonInt       `json:"profileNonce"`
	Challenge    *jsonInt       `json:"challenge"`
	Signature    *jsonSignature `json:"signature"`
}

func (a *AuthV3Inputs) UnmarshalJSON(bytes []byte) error {
	aux := authV3Json{authV3JsonAlias: (*authV3JsonAlias)(a)}
	err := json.Unmarshal(bytes, &aux)
	if err != nil {
		return err
	}
	a.ProfileNonce = aux.ProfileNonce.BigInt()
	a.Challenge = aux.Challenge.BigInt()
	a.Signature = (*babyjub.Signature)(aux.Signature)
	return nil
}

func (a AuthV3Inputs) MarshalJSON() ([]byte, error) {
	return json.Marshal(&authV3Json{
		authV3JsonAlias: (*authV3JsonAlias)(&a),
		ProfileNonce:    (*jsonInt)(a.ProfileNonce),
		Challenge:       (*jsonInt)(a.Challenge),
		Signature:       (*jsonSignature)(a.Signature),
	})
}

// AuthV3PubSignals authV3.circom/authV3-8-32.circom public signals
type AuthV3PubSignals struct {
	UserID    *core.ID         `json:"userID"`
	Challenge *big.Int         `json:"challenge"`
	GISTRoot  *merkletree.Hash `json:"GISTRoot"`
}

// PubSignalsUnmarshal unmarshal authV3.circom/authV3-8-32.circom public inputs to AuthPubSignals
func (a *AuthV3PubSignals) PubSignalsUnmarshal(data []byte) error {
	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != 3 {
		return fmt.Errorf("invalid number of Output values expected {%d} got {%d} ", 3, len(sVals))
	}

	if a.UserID, err = idFromIntStr(sVals[0]); err != nil {
		return err
	}

	var ok bool
	if a.Challenge, ok = big.NewInt(0).SetString(sVals[1], 10); !ok {
		return fmt.Errorf("invalid challenge value: '%s'", sVals[0])
	}

	if a.GISTRoot, err = merkletree.NewHashFromString(sVals[2]); err != nil {
		return err
	}

	return nil
}

// GetObjMap returns AuthPubSignals as a map
func (a AuthV3PubSignals) GetObjMap() map[string]interface{} {
	return toMap(a)
}

func (a AuthV3PubSignals) GetStatesInfo() (StatesInfo, error) {
	if a.UserID == nil {
		return StatesInfo{}, errors.New(ErrorEmptyID)
	}
	if a.GISTRoot == nil {
		return StatesInfo{}, errors.New(ErrorEmptyStateHash)
	}
	return StatesInfo{
		States: []State{},
		Gists:  []Gist{{ID: *a.UserID, Root: *a.GISTRoot}},
	}, nil
}
