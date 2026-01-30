package circuits

import (
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
)

// MinCircuitInput is a type constraint for inputs that support minimal circuit
// selection.
type MinCircuitInput interface {
	*AtomicQueryV3Inputs | *AtomicQueryV3OnChainInputs | *AuthV3Inputs
}

// AdjustInputsForMinCircuit inspects the provided circuit inputs, selects
// the smallest circuit variant that can accommodate them, and modifies
// the input's configuration in place.
func AdjustInputsForMinCircuit[T MinCircuitInput](input T) (CircuitID, error) {
	switch v := any(input).(type) {
	case *AtomicQueryV3Inputs:
		if v == nil {
			return "", errors.New(ErrorInputsTypeNotSupported)
		}
		circuitID, cfg, err := minCircuitForAtomicQueryV3(*v)
		if err != nil {
			return "", err
		}
		v.BaseConfig = cfg
		return circuitID, nil
	case *AtomicQueryV3OnChainInputs:
		if v == nil {
			return "", errors.New(ErrorInputsTypeNotSupported)
		}
		circuitID, cfg, err := minCircuitForAtomicQueryV3OnChain(*v)
		if err != nil {
			return "", err
		}
		v.BaseConfig = cfg
		return circuitID, nil
	case *AuthV3Inputs:
		if v == nil {
			return "", errors.New(ErrorInputsTypeNotSupported)
		}
		circuitID, cfg, err := minCircuitForAuthV3(*v)
		if err != nil {
			return "", err
		}
		v.BaseConfig = cfg
		return circuitID, nil
	default:
		return "", errors.New(ErrorInputsTypeNotSupported)
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
