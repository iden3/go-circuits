package circuits

import (
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"math/big"
)

// BatchSize defined by poseidon hash implementation in Solidity
const BatchSize = 6

func poseidonHash(values []*big.Int) (*big.Int, error) {

	if values == nil || len(values) == 0 {
		return nil, errors.New("values not provided")
	}

	l := len(values)
	r := l % BatchSize
	diff := BatchSize - r
	iterationCount := (l+diff)/BatchSize + 1
	fullHash := big.NewInt(0)
	var err error
	getIndex := func(idx, length int) int {
		if idx < length {
			return idx
		}
		return 0
	}
	for i := 0; i < iterationCount; i++ {
		elemIdx := i * BatchSize
		fullHash, err = poseidon.Hash([]*big.Int{
			fullHash,
			values[getIndex(elemIdx, l)],
			values[getIndex(elemIdx+1, l)],
			values[getIndex(elemIdx+2, l)],
			values[getIndex(elemIdx+3, l)],
			values[getIndex(elemIdx+4, l)],
		})
		if err != nil {
			return nil, err
		}
	}

	return fullHash, nil

}
