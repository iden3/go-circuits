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

func TestStateTransitionOutput_GetJSONObj(t *testing.T) {
	id, err := core.IDFromString("1124NoAu14diR5EM1kgUha2uHFkvUrPrTXMtf4tncZ")
	assert.Nil(t, err)

	newState := hashPtrFromInt(big.NewInt(1))
	oldState := hashPtrFromInt(big.NewInt(2))

	sto := StateTransitionPubSignals{
		UserID:       &id,
		OldUserState: oldState,
		NewUserState: newState,
	}

	m := sto.GetObjMap()
	assert.Equal(t, &id, m["userID"])
	assert.Equal(t, oldState, m["oldUserState"])
	assert.Equal(t, newState, m["newUserState"])

}

func TestStateTransitionInputs_InputsMarshal(t *testing.T) {

	out := new(StateTransitionPubSignals)
	err := out.PubSignalsUnmarshal([]byte(`
	[
	"23148936466334350744548790012294489365207440754509988986684797708370051073",
	"7115004997868594253010848596868364067574661249707337517331323113105592633327",
	"4546963942567895423749885008322935416520496550192665955639269179690288593086",
	"0"
	]`))
	require.NoError(t, err)

	userIDStr, b := new(big.Int).SetString(
		"23148936466334350744548790012294489365207440754509988986684797708370051073", 10)
	assert.True(t, b)
	userID, err := core.IDFromInt(userIDStr)
	require.NoError(t, err)

	oldUserState, err := merkletree.NewHashFromString(
		"7115004997868594253010848596868364067574661249707337517331323113105592633327")
	require.NoError(t, err)

	newUserState, err := merkletree.NewHashFromString(
		"4546963942567895423749885008322935416520496550192665955639269179690288593086")
	require.NoError(t, err)

	exp := StateTransitionPubSignals{
		UserID:            &userID,
		OldUserState:      oldUserState,
		NewUserState:      newUserState,
		IsOldStateGenesis: false,
	}

	jsonOut, err := json.Marshal(out)
	require.NoError(t, err)
	jsonExp, err := json.Marshal(exp)
	require.NoError(t, err)

	require.JSONEq(t, string(jsonExp), string(jsonOut))
}
