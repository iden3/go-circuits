package circuits

import (
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
)

// SelectMinCircuitForInputs inspects the provided circuit inputs and selects
// the smallest circuit variant that can accommodate them.
//
// It analyzes merkle proof depths and query value array sizes to determine
// the minimum required circuit configuration, returning:
//   - CircuitID: the specific circuit variant identifier
//   - BaseConfig: the configuration to use when marshaling inputs
//   - error: if the input type is unsupported or exceeds all available presets
//
// Supported input types:
//   - AtomicQueryV3Inputs / *AtomicQueryV3Inputs
//   - AtomicQueryV3OnChainInputs / *AtomicQueryV3OnChainInputs
//   - AuthV3Inputs / *AuthV3Inputs
//
// The returned BaseConfig should be assigned to the input's BaseConfig field
// before calling InputsMarshal() to ensure correct array padding.
func SelectMinCircuitForInputs(input any) (CircuitID, BaseConfig, error) {
	switch v := input.(type) {
	case AtomicQueryV3Inputs:
		return minCircuitForAtomicQueryV3(v)
	case *AtomicQueryV3Inputs:
		if v == nil {
			return "", BaseConfig{}, errors.New(ErrorInputsTypeNotSupported)
		}
		return minCircuitForAtomicQueryV3(*v)
	case AtomicQueryV3OnChainInputs:
		return minCircuitForAtomicQueryV3OnChain(v)
	case *AtomicQueryV3OnChainInputs:
		if v == nil {
			return "", BaseConfig{}, errors.New(ErrorInputsTypeNotSupported)
		}
		return minCircuitForAtomicQueryV3OnChain(*v)
	case AuthV3Inputs:
		return minCircuitForAuthV3(v)
	case *AuthV3Inputs:
		if v == nil {
			return "", BaseConfig{}, errors.New(ErrorInputsTypeNotSupported)
		}
		return minCircuitForAuthV3(*v)
	default:
		return "", BaseConfig{}, errors.New(ErrorInputsTypeNotSupported)
	}
}

func minCircuitForAtomicQueryV3(a AtomicQueryV3Inputs) (CircuitID, BaseConfig, error) {
	mtReq, mtClaimReq, valueReq := atomicQueryV3Requirements(a.Claim, a.Query, a.ProofType)

	if fitsAtomicQueryV3Config(mtReq, mtClaimReq, valueReq, presetCfg16_16_64_32) {
		return CircuitID(string(AtomicQueryV3StableCircuitID) + "-16-16-64"), presetCfg16_16_64_32, nil
	}
	if fitsAtomicQueryV3Config(mtReq, mtClaimReq, valueReq, presetCfg40_32_64_64) {
		return AtomicQueryV3StableCircuitID, presetCfg40_32_64_64, nil
	}
	return "", BaseConfig{}, errors.New(ErrorInputsTooLarge)
}

func minCircuitForAtomicQueryV3OnChain(a AtomicQueryV3OnChainInputs) (CircuitID, BaseConfig, error) {
	mtReq, mtClaimReq, valueReq := atomicQueryV3Requirements(a.Claim, a.Query, a.ProofType)
	mtOnChainReq := 0

	if a.IsBJJAuthEnabled == 1 {
		mtReq = max(mtReq,
			proofSiblingsLen(a.AuthClaimIncMtp),
			proofSiblingsLen(a.AuthClaimNonRevMtp),
		)
		mtOnChainReq = proofSiblingsLen(a.GISTProof.Proof)
	}

	if fitsAtomicQueryV3OnChainConfig(mtReq, mtClaimReq, valueReq, mtOnChainReq, presetCfg16_16_64_32) {
		return CircuitID(string(AtomicQueryV3OnChainStableCircuitID) + "-16-16-64-16-32"), presetCfg16_16_64_32, nil
	}
	if fitsAtomicQueryV3OnChainConfig(mtReq, mtClaimReq, valueReq, mtOnChainReq, presetCfg40_32_64_64) {
		return AtomicQueryV3OnChainStableCircuitID, presetCfg40_32_64_64, nil
	}
	return "", BaseConfig{}, errors.New(ErrorInputsTooLarge)
}

func minCircuitForAuthV3(a AuthV3Inputs) (CircuitID, BaseConfig, error) {
	mtReq := max(
		proofSiblingsLen(a.AuthClaimIncMtp),
		proofSiblingsLen(a.AuthClaimNonRevMtp),
	)
	mtOnChainReq := proofSiblingsLen(a.GISTProof.Proof)

	if fitsAuthV3Config(mtReq, mtOnChainReq, presetCfg8_32) {
		return AuthV3_8_32CircuitID, presetCfg8_32, nil
	}
	if fitsAuthV3Config(mtReq, mtOnChainReq, presetCfg40_32_64_64) {
		return AuthV3CircuitID, presetCfg40_32_64_64, nil
	}
	return "", BaseConfig{}, errors.New(ErrorInputsTooLarge)
}

func atomicQueryV3Requirements(
	claim ClaimWithSigAndMTPProof,
	query Query,
	proofType ProofType,
) (mtReq, mtClaimReq, valueReq int) {
	mtReq = proofSiblingsLen(claim.NonRevProof.Proof)

	switch proofType {
	case BJJSignatureProofType:
		if claim.SignatureProof != nil {
			mtReq = max(
				mtReq,
				proofSiblingsLen(claim.SignatureProof.IssuerAuthIncProof.Proof),
				proofSiblingsLen(claim.SignatureProof.IssuerAuthNonRevProof.Proof),
			)
		}
	case Iden3SparseMerkleTreeProofType:
		if claim.IncProof != nil {
			mtReq = max(mtReq, proofSiblingsLen(claim.IncProof.Proof))
		}
	}

	if query.ValueProof != nil {
		mtClaimReq = proofSiblingsLen(query.ValueProof.MTP)
	}
	valueReq = len(query.Values)

	return mtReq, mtClaimReq, valueReq
}

func fitsAtomicQueryV3Config(mtReq, mtClaimReq, valueReq int, cfg BaseConfig) bool {
	return mtReq <= cfg.GetMTLevel() &&
		mtClaimReq <= cfg.GetMTLevelsClaim() &&
		valueReq <= cfg.GetValueArrSize()
}

func fitsAtomicQueryV3OnChainConfig(mtReq, mtClaimReq, valueReq, mtOnChainReq int, cfg BaseConfig) bool {
	return mtReq <= cfg.GetMTLevel() &&
		mtClaimReq <= cfg.GetMTLevelsClaim() &&
		valueReq <= cfg.GetValueArrSize() &&
		mtOnChainReq <= cfg.GetMTLevelOnChain()
}

func fitsAuthV3Config(mtReq, mtOnChainReq int, cfg BaseConfig) bool {
	return mtReq <= cfg.GetMTLevel() &&
		mtOnChainReq <= cfg.GetMTLevelOnChain()
}

func proofSiblingsLen(proof *merkletree.Proof) int {
	if proof == nil {
		return 0
	}
	return len(proof.AllSiblings())
}
