package circuits

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql/v2"
)

type jsonInt big.Int

func (j *jsonInt) UnmarshalJSON(bytes []byte) error {
	var s string
	if err := json.Unmarshal(bytes, &s); err != nil {
		return err
	}
	var i = (*big.Int)(j)
	_, ok := i.SetString(s, 10)
	if !ok {
		return errors.New("error parsing big.Int")
	}
	return nil
}

func (j *jsonInt) MarshalJSON() ([]byte, error) {
	if j == nil {
		return []byte("null"), nil
	}

	return json.Marshal((*big.Int)(j).String())
}

func (j *jsonInt) BigInt() *big.Int {
	if j == nil {
		return nil
	}
	return (*big.Int)(j)
}

type jsonSignature babyjub.Signature

func (s *jsonSignature) UnmarshalJSON(bytes []byte) error {
	var sHex string
	if err := json.Unmarshal(bytes, &sHex); err != nil {
		return err
	}
	sigComp, err := hex.DecodeString(sHex)
	if err != nil {
		return err
	}
	var sigComp2 babyjub.SignatureComp
	if len(sigComp2) != len(sigComp) {
		return errors.New("incorrect signature length")
	}
	copy(sigComp2[:], sigComp)
	sig, err := sigComp2.Decompress()
	if err != nil {
		return err
	}
	*((*babyjub.Signature)(s)) = *sig
	return nil
}

func (s *jsonSignature) MarshalJSON() ([]byte, error) {
	if s == nil {
		return []byte("null"), nil
	}

	bs := babyjub.Signature(*s)
	sigComp := bs.Compress()
	return json.Marshal(hex.EncodeToString(sigComp[:]))
}

type jsonInputs struct {
	GenesisID          *core.ID          `json:"genesisID"`
	ProfileNonce       *jsonInt          `json:"profileNonce"`
	AuthClaim          *core.Claim       `json:"authClaim"`
	AuthClaimIncMtp    *merkletree.Proof `json:"authClaimIncMtp"`
	AuthClaimNonRevMtp *merkletree.Proof `json:"authClaimNonRevMtp"`
	TreeState          TreeState         `json:"treeState"` // Identity state
	GISTProof          GISTProof         `json:"gistProof"`
	Signature          *jsonSignature    `json:"signature"`
	Challenge          *jsonInt          `json:"challenge"`
}

func newJsonInputs(a AuthV2Inputs) jsonInputs {
	var inputs jsonInputs
	inputs.GenesisID = a.GenesisID
	inputs.ProfileNonce = (*jsonInt)(a.ProfileNonce)
	inputs.AuthClaim = a.AuthClaim
	inputs.AuthClaimIncMtp = a.AuthClaimIncMtp
	inputs.AuthClaimNonRevMtp = a.AuthClaimNonRevMtp
	inputs.TreeState = a.TreeState
	inputs.GISTProof = a.GISTProof
	inputs.Signature = (*jsonSignature)(a.Signature)
	inputs.Challenge = (*jsonInt)(a.Challenge)
	return inputs
}

func (inputs jsonInputs) Unwrap() AuthV2Inputs {
	var a AuthV2Inputs
	a.GenesisID = inputs.GenesisID
	a.ProfileNonce = (*big.Int)(inputs.ProfileNonce)
	a.AuthClaim = inputs.AuthClaim
	a.AuthClaimIncMtp = inputs.AuthClaimIncMtp
	a.AuthClaimNonRevMtp = inputs.AuthClaimNonRevMtp
	a.TreeState = inputs.TreeState
	a.GISTProof = inputs.GISTProof
	a.Signature = (*babyjub.Signature)(inputs.Signature)
	a.Challenge = (*big.Int)(inputs.Challenge)
	return a
}

func (a AuthV2Inputs) MarshalJSON() ([]byte, error) {
	return json.Marshal(newJsonInputs(a))
}

func (a *AuthV2Inputs) UnmarshalJSON(in []byte) error {
	var inputs jsonInputs
	err := json.Unmarshal(in, &inputs)
	if err != nil {
		return err
	}
	*a = inputs.Unwrap()
	return nil
}
