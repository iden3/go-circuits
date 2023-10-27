package verifier

import (
	"fmt"
	"math/big"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// CalculateLinkID returns linkID calculated from linkNonce and claim
func CalculateLinkID(linkNonce string, claim *core.Claim) (string, error) {
	if linkNonce == "0" {
		return "0", nil
	}

	nonceInt, ok := big.NewInt(0).SetString(linkNonce, 10)

	if !ok {
		return "", fmt.Errorf("invalid linkNonce value: '%s'", linkNonce)
	}

	hi, hv, err := claim.HiHv()
	if err != nil {
		return "", err
	}

	claimHash, err := poseidon.Hash([]*big.Int{hi, hv})
	if err != nil {
		return "", err
	}

	linkID, err := poseidon.Hash([]*big.Int{claimHash, nonceInt})
	if err != nil {
		return "", err
	}

	return linkID.String(), nil
}
