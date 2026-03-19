package circuits

// Circuit configuration presets for minimal circuit selection.
//
// These presets correspond to circuit template instantiation parameters:
//   - MTLevel        → issuerLevels (also used as idOwnershipLevels)
//   - MTLevelClaim   → claimLevels
//   - ValueArraySize → maxValueArraySize
//   - MTLevelOnChain → onChainLevels
//
// Circuit mappings:
//   - credentialAtomicQueryV3.circom                    → (40, 32, 64)
//   - credentialAtomicQueryV3-16-16-64.circom           → (16, 16, 64)
//   - credentialAtomicQueryV3OnChain.circom             → (40, 32, 64, 40, 64)
//   - credentialAtomicQueryV3OnChain-16-16-64-16-32     → (16, 16, 64, 16, 32)
//   - authV3.circom                                     → (40, 64)
//   - authV3-8-32.circom                                → (8, 32)
var (
	// presetCfg40_32_64_64 is the large/default configuration for V3 circuits.
	presetCfg40_32_64_64 = BaseConfig{
		MTLevel:        40,
		MTLevelClaim:   32,
		ValueArraySize: 64,
		MTLevelOnChain: 64,
	}

	// presetCfg16_16_64_32 is the small configuration for V3 circuits,
	// suitable for proofs with shallower merkle trees.
	presetCfg16_16_64_32 = BaseConfig{
		MTLevel:        16,
		MTLevelClaim:   16,
		ValueArraySize: 64,
		MTLevelOnChain: 32,
	}

	// presetCfg8_32 is the small configuration for AuthV3 circuits.
	// Only MTLevel and MTLevelOnChain are used by auth circuits.
	presetCfg8_32 = BaseConfig{
		MTLevel:        8,
		MTLevelOnChain: 32,
	}
)
