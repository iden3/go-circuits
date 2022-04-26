package circuits

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalCircuitOutput(t *testing.T) {

	id, err := core.IDFromString("11AVZrKNJVqDJoyKrdyaAgEynyBEjksV5z2NjZoPxf")
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

func TestGetVerificationKey(t *testing.T) {

	got, err := GetVerificationKey(AuthCircuitID)
	assert.NoError(t, err)

	fmt.Println(string(got))
}
