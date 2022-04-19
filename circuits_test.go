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
	userState := merkletree.NewHashFromBigInt(big.NewInt(12))
	out := AuthOutputs{
		Challenge: challenge,
		UserState: userState,
		UserID:    &id,
	}

	json, err := json.Marshal(out)
	assert.Nil(t, err)

	got, err := UnmarshalCircuitOutput(AuthCircuitID, json)
	assert.Nil(t, err)

	assert.Equal(t, got["UserID"], &id)
	assert.Equal(t, got["Challenge"], challenge)
	assert.Equal(t, got["UserState"], userState)
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
