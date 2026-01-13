package circuits

// AllOperations is a list of all available query operators.
var AllOperations = func() []int {
	ops := make([]int, 0, len(QueryOperators))
	for _, v := range QueryOperators {
		ops = append(ops, v)
	}
	return ops
}()

// V2Operations is a list of all available query operators in V2.
var V2Operations = []int{
	NOOP, EQ, LT, GT, IN, NIN, NE, SD,
}

// V2OnChainOperations is a list of all available on-chain query operators in V2.
var V2OnChainOperations = []int{
	EQ, LT, GT, IN, NIN, NE,
}

// Validation struct contains parameters for query validation.
type Validation struct {
	MaxQueriesCount     int
	SupportedOperations []int
}

// CircuitSubversion struct represents differences in circuit versions.
type CircuitSubversion struct {
	MTLevel         *int
	MTLevelClaim    *int
	MTLevelOnChain  *int
	QueryCount      *int
	TargetCircuitId CircuitID
}

// CircuitValidatorItem struct represents a circuit validation item with its subversions.
type CircuitValidatorItem struct {
	Validation  Validation
	SubVersions []CircuitSubversion
}

var noQueriesValidation = CircuitValidatorItem{
	Validation: Validation{
		MaxQueriesCount:     0,
		SupportedOperations: []int{},
	},
}

var credentialAtomicQueryV2Validation = CircuitValidatorItem{
	Validation: Validation{
		MaxQueriesCount:     1,
		SupportedOperations: V2Operations,
	},
}

var credentialAtomicQueryV2OnChainValidation = CircuitValidatorItem{
	Validation: Validation{
		MaxQueriesCount:     1,
		SupportedOperations: V2OnChainOperations,
	},
}

var credentialAtomicQueryV3Validation = CircuitValidatorItem{
	Validation: Validation{
		MaxQueriesCount:     1,
		SupportedOperations: AllOperations,
	},
}

// CircuitValidator map contains validation rules for each circuit ID.
var CircuitValidator = map[CircuitID]CircuitValidatorItem{
	AtomicQueryMTPV2CircuitID:        credentialAtomicQueryV2Validation,
	AtomicQueryMTPV2OnChainCircuitID: credentialAtomicQueryV2OnChainValidation,
	AtomicQuerySigV2CircuitID:        credentialAtomicQueryV2Validation,
	AtomicQuerySigV2OnChainCircuitID: credentialAtomicQueryV2OnChainValidation,
	AtomicQueryV3CircuitID:           credentialAtomicQueryV3Validation,
	AtomicQueryV3OnChainCircuitID:    credentialAtomicQueryV3Validation,
	AuthV2CircuitID:                  noQueriesValidation,
	AuthV3CircuitID:                  noQueriesValidation,
	AuthV3_8_32CircuitID:             noQueriesValidation,
	StateTransitionCircuitID:         noQueriesValidation,
	LinkedMultiQuery10CircuitID: {
		Validation: Validation{
			MaxQueriesCount:     10,
			SupportedOperations: AllOperations,
		},
	},

	AtomicQueryV3StableCircuitID: {
		Validation: credentialAtomicQueryV3Validation.Validation,
		SubVersions: []CircuitSubversion{
			{
				MTLevel:         intPtr(16),
				MTLevelClaim:    intPtr(16),
				TargetCircuitId: CircuitID(string(AtomicQueryV3StableCircuitID) + "-16-16-64"),
			},
		},
	},

	AtomicQueryV3OnChainStableCircuitID: {
		Validation: credentialAtomicQueryV3Validation.Validation,
		SubVersions: []CircuitSubversion{
			{
				MTLevel:         intPtr(16),
				MTLevelClaim:    intPtr(16),
				MTLevelOnChain:  intPtr(32),
				TargetCircuitId: CircuitID(string(AtomicQueryV3OnChainStableCircuitID) + "-16-16-64-16-32"),
			},
		},
	},

	LinkedMultiQuery10StableCircuitID: {
		Validation: Validation{
			MaxQueriesCount:     10,
			SupportedOperations: AllOperations,
		},
		SubVersions: []CircuitSubversion{
			{
				QueryCount:      intPtr(3),
				TargetCircuitId: CircuitID(string(LinkedMultiQuery10StableCircuitID[:len(LinkedMultiQuery10StableCircuitID)-2]) + "3"),
			},
			{
				QueryCount:      intPtr(5),
				TargetCircuitId: CircuitID(string(LinkedMultiQuery10StableCircuitID[:len(LinkedMultiQuery10StableCircuitID)-2]) + "5"),
			},
		},
	},
}

func intPtr(v int) *int { return &v }

// GetCircuitIdsWithSubVersions returns all circuit IDs including their sub-versions for a given filter.
func GetCircuitIdsWithSubVersions(filter []CircuitID) []CircuitID {
	filterSet := map[CircuitID]struct{}{}
	for _, id := range filter {
		filterSet[id] = struct{}{}
	}

	acc := map[CircuitID]struct{}{}

	for id, item := range CircuitValidator {
		if len(filterSet) > 0 {
			if _, ok := filterSet[id]; !ok {
				continue
			}
		}

		acc[id] = struct{}{}
		for _, sv := range item.SubVersions {
			acc[sv.TargetCircuitId] = struct{}{}
		}
	}

	out := make([]CircuitID, 0, len(acc))
	for id := range acc {
		out = append(out, id)
	}
	return out
}

// GetGroupedCircuitIdsWithSubVersions returns all circuit IDs grouped with their sub-versions for a given filter ID.
func GetGroupedCircuitIdsWithSubVersions(filter CircuitID) []CircuitID {
	for base, item := range CircuitValidator {
		group := []CircuitID{base}
		for _, sv := range item.SubVersions {
			group = append(group, sv.TargetCircuitId)
		}

		for _, id := range group {
			if id == filter {
				return group
			}
		}
	}

	if item, ok := CircuitValidator[filter]; ok {
		group := []CircuitID{filter}
		for _, sv := range item.SubVersions {
			group = append(group, sv.TargetCircuitId)
		}
		return group
	}

	return []CircuitID{filter}
}
