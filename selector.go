package circuits

import "github.com/iden3/go-merkletree-sql/v2"

// TreesToCheck holds a Merkle proof and the corresponding level key to check against.
type TreesToCheck struct {
	Proof    *merkletree.Proof
	LevelKey LevelKey
}

// LevelKey tells which depth field of CircuitSubversion to use.
type LevelKey int

const (
	LevelMT LevelKey = iota
	LevelMTClaim
	LevelMTOnChain
)

// Get retrieves the corresponding level depth from CircuitSubversion.
func (k LevelKey) Get(sv CircuitSubversion) *int {
	switch k {
	case LevelMT:
		return sv.MTLevel
	case LevelMTClaim:
		return sv.MTLevelClaim
	case LevelMTOnChain:
		return sv.MTLevelOnChain
	default:
		return nil
	}
}

// SelectV3TargetCircuit selects the appropriate CircuitSubversion for V3 circuits
func SelectV3TargetCircuit(
	circuitID CircuitID,
	treesToCheck []TreesToCheck,
	isOnChain bool,
) *CircuitSubversion {
	item, ok := CircuitValidator[circuitID]
	if !ok || len(item.SubVersions) == 0 {
		return nil
	}

	for i := range item.SubVersions {
		sv := item.SubVersions[i]

		if sv.MTLevel == nil || sv.MTLevelClaim == nil || (isOnChain && sv.MTLevelOnChain == nil) {
			continue
		}

		mtLevelsValid := true
		for _, tc := range treesToCheck {
			if tc.Proof == nil {
				continue
			}

			levelDepthPtr := tc.LevelKey.Get(sv)
			if levelDepthPtr == nil {
				continue
			}
			levelDepth := *levelDepthPtr

			if len(tc.Proof.AllSiblings()) > levelDepth-1 {
				mtLevelsValid = false
				break
			}
		}

		if mtLevelsValid {
			return &CircuitSubversion{
				MTLevel:         sv.MTLevel,
				MTLevelClaim:    sv.MTLevelClaim,
				MTLevelOnChain:  sv.MTLevelOnChain,
				TargetCircuitId: sv.TargetCircuitId,
			}
		}
	}
	return nil
}
