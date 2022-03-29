package circuits

import (
	"math/big"

	"github.com/pkg/errors"
)

// Query represents basic request to claim slot verification
type Query struct {
	SlotIndex int
	Values    []*big.Int
	Operator  int
}

// QueryOperators represents operators for atomic circuits
var QueryOperators = map[string]int{
	"$eq":  0,
	"$lt":  1,
	"$gt":  2,
	"$in":  3,
	"$nin": 4,
}

// Comparer value.
type Comparer interface {
	Compare(int) (bool, error)
}

// Scalar uses for compare two scalar value.
type Scalar struct {
	x, y *big.Int
}

// NewScalar create `Scalar` comparer.
func NewScalar(x, y *big.Int) *Scalar {
	return &Scalar{x, y}
}

// Compare x with y by target QueryOperators.
// Scalar compare support: $eq, $lt, $gt type.
func (s *Scalar) Compare(t int) (bool, error) {
	switch t {
	case 0: // eq
		return s.x.Cmp(s.y) == 0, nil
	case 1: // lt
		return s.x.Cmp(s.y) == -1, nil
	case 2: // gt
		return s.x.Cmp(s.y) == 1, nil
	}
	return false, errors.New("unknown compare type for scalar")
}

// Vector uses for find/not find x scalar type in y vector type.
type Vector struct {
	x *big.Int
	y []*big.Int
}

// NewVector create Vector.
func NewVector(x *big.Int, y []*big.Int) *Vector {
	return &Vector{x, y}
}

// Compare find/not find x in y by type.
// Vector compare support: $in, $nin
func (v *Vector) Compare(t int) (bool, error) {
	switch t {
	case 3: // in
		if len(v.y) == 0 {
			return false, nil
		}
		for _, i := range v.y {
			if v.x.Cmp(i) == 0 {
				return true, nil
			}
		}
		return false, nil
	case 4: // nin
		if len(v.y) == 0 {
			return true, nil
		}
		for _, i := range v.y {
			if v.x.Cmp(i) == 0 {
				return false, nil
			}
		}
		return true, nil
	}
	return false, errors.New("unknown compare type for vector")
}

// FactoryComparer depends on input data will return right comparer.
func FactoryComparer(x *big.Int, y []*big.Int, t int) (Comparer, error) {
	var cmp Comparer
	switch t {
	// eq, lh, gh
	case 0, 1, 2:
		if len(y) != 1 {
			return nil, errors.New("currently we support only one value for scalar comparison")
		}
		cmp = NewScalar(x, y[0])
	// in, nin.
	case 3, 4:
		cmp = NewVector(x, y)
	default:
		return nil, errors.New("unknown compare type")
	}
	return cmp, nil
}
