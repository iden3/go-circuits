package circuits

import (
	"encoding/json"
	"math/big"
	"testing"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalCircuitOutput(t *testing.T) {

	id, err := core.IDFromString("1124NoAu14diR5EM1kgUha2uHFkvUrPrTXMtf4tncZ")
	assert.Nil(t, err)

	challenge := big.NewInt(11)
	userState, err := merkletree.NewHashFromBigInt(big.NewInt(12))
	assert.NoError(t, err)

	out := []string{challenge.String(), userState.BigInt().String(),
		id.BigInt().String()}

	json, err := json.Marshal(out)
	assert.Nil(t, err)

	got, err := UnmarshalCircuitOutput(AuthCircuitID, json)
	assert.Nil(t, err)

	assert.Equal(t, got["userID"], &id)
	assert.Equal(t, got["challenge"], challenge)
	assert.Equal(t, got["userState"], userState)
}

func TestUnmarshalCircuitOutput_Err(t *testing.T) {

	_, err := UnmarshalCircuitOutput("Err", []byte("{}"))

	assert.Equal(t, err, ErrorCircuitIDNotFound)
}

func TestGistJsonMarshallers(t *testing.T) {
	var in Gist
	var err error
	in.ID, err = core.IDFromString("tQomzpDTB6x4EJUaiwk153FVi96jeNfP9WjKp9xys")
	require.NoError(t, err)

	h, err := merkletree.NewHashFromString("11098939821764568131087645431296528907277253709936443029379587475821759259406")
	require.NoError(t, err)
	in.Root = *h

	wantJson := `{
  "id": "26109404700696283154998654512117952420503675471097392618762221546565140481",
  "root": "11098939821764568131087645431296528907277253709936443029379587475821759259406"
}`

	inJsonBytes, err := json.Marshal(in)
	require.NoError(t, err)

	require.JSONEq(t, wantJson, string(inJsonBytes))

	var out Gist
	err = json.Unmarshal(inJsonBytes, &out)
	require.NoError(t, err)
	require.Equal(t, in, out)
}

func TestStateJsonMarshallers(t *testing.T) {
	var in State
	var err error
	in.ID, err = core.IDFromString("tQomzpDTB6x4EJUaiwk153FVi96jeNfP9WjKp9xys")
	require.NoError(t, err)

	h, err := merkletree.NewHashFromString("11098939821764568131087645431296528907277253709936443029379587475821759259406")
	require.NoError(t, err)
	in.State = *h

	wantJson := `{
  "id": "26109404700696283154998654512117952420503675471097392618762221546565140481",
  "state": "11098939821764568131087645431296528907277253709936443029379587475821759259406"
}`

	inJsonBytes, err := json.Marshal(in)
	require.NoError(t, err)

	require.JSONEq(t, wantJson, string(inJsonBytes))

	var out State
	err = json.Unmarshal(inJsonBytes, &out)
	require.NoError(t, err)
	require.Equal(t, in, out)
}
