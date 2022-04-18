package circuits

import (
	"math/big"
	"testing"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql"
	"github.com/stretchr/testify/assert"
)

func TestStateTransitionOutput_GetJSONObj(t *testing.T) {
	id, err := core.IDFromString("11AVZrKNJVqDJoyKrdyaAgEynyBEjksV5z2NjZoPxf")
	assert.Nil(t, err)

	newState := merkletree.NewHashFromBigInt(big.NewInt(1))
	oldState := merkletree.NewHashFromBigInt(big.NewInt(2))

	sto := StateTransitionOutput{
		UserID:       &id,
		OldUserState: oldState,
		NewUserState: newState,
	}

	m := sto.GetJSONObjMap()
	assert.Equal(t, &id, m["UserID"])
	assert.Equal(t, oldState, m["OldUserState"])
	assert.Equal(t, newState, m["NewUserState"])

}
