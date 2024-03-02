package circuits

import (
	"math/big"

	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
)

// List of available operators.
const (
	NOOP int = iota // No operation, skip query verification in circuit
	EQ
	LT
	GT
	IN
	NIN
	NE
	LTE
	GTE
	BETWEEN
	NONBETWEEN
	EXISTS
	SD      = 16
	NULLIFY = 17
)

// QueryOperators represents operators for atomic circuits
var QueryOperators = map[string]int{
	"$noop":       NOOP,
	"$eq":         EQ,
	"$lt":         LT,
	"$gt":         GT,
	"$in":         IN,
	"$nin":        NIN,
	"$ne":         NE,
	"$lte":        LTE,
	"$gte":        GTE,
	"$between":    BETWEEN,
	"$nonbetween": NONBETWEEN,
	"$exists":     EXISTS,
	"$sd":         SD,
	"$nullify":    NULLIFY,
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
// Scalar compare support: $eq, $lt, $gt, $ne, $lte, $gte type.
func (s *Scalar) Compare(t int) (bool, error) {
	compare := s.x.Cmp(s.y)
	switch t {
	case EQ:
		return compare == 0, nil
	case LT:
		return compare == -1, nil
	case GT:
		return compare == 1, nil
	case NE:
		return compare != 0, nil
	case LTE:
		return compare < 1, nil
	case GTE:
		return compare > -1, nil
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
// Vector compare support: $in, $nin, $between
func (v *Vector) Compare(t int) (bool, error) {
	switch t {
	case IN:
		if len(v.y) == 0 {
			return false, nil
		}
		for _, i := range v.y {
			if v.x.Cmp(i) == 0 {
				return true, nil
			}
		}
		return false, nil
	case NIN:
		if len(v.y) == 0 {
			return true, nil
		}
		for _, i := range v.y {
			if v.x.Cmp(i) == 0 {
				return false, nil
			}
		}
		return true, nil
	case BETWEEN:
		if len(v.y) < 2 {
			return false, nil
		}
		if v.x.Cmp(v.y[0]) >= 0 && v.x.Cmp(v.y[1]) <= 0 {
			return true, nil
		}
		return false, nil
	case NONBETWEEN:
		if len(v.y) < 2 {
			return false, nil
		}
		if !(v.x.Cmp(v.y[0]) >= 0 && v.x.Cmp(v.y[1]) <= 0) {
			return true, nil
		}
		return false, nil
	}
	return false, errors.New("unknown compare type for vector")
}

// FactoryComparer depends on input data will return right comparer.
func FactoryComparer(x *big.Int, y []*big.Int, t int) (Comparer, error) {
	var cmp Comparer
	switch t {
	case EQ, LT, GT, NE:
		if len(y) != 1 {
			return nil, errors.New("currently we support only one value for scalar comparison")
		}
		cmp = NewScalar(x, y[0])
	case IN, NIN:
		cmp = NewVector(x, y)
	default:
		return nil, errors.New("unknown compare type")
	}
	return cmp, nil
}

// Query represents basic request to claim field with MTP and without
type Query struct {
	Operator   int
	Values     []*big.Int
	SlotIndex  int
	ValueProof *ValueProof
}

// Validate value size for operator
func (q Query) ValidateValueArraySize(maxArrSize int) error {
	oneArrLengthOps := []int{EQ, LT, GT, NE, LTE, GTE, EXISTS}
	twoArrLengthOps := []int{BETWEEN, NONBETWEEN}
	maxArrLengthOps := []int{IN, NIN}

	arrSize := len(q.Values)
	if contains(oneArrLengthOps, q.Operator) {
		if arrSize != 1 {
			return errors.New(ErrorInvalidValuesArrSize)
		} else {
			return nil
		}
	}
	if contains(twoArrLengthOps, q.Operator) {
		if arrSize != 2 {
			return errors.New(ErrorInvalidValuesArrSize)
		} else {
			return nil
		}
	}
	if contains(maxArrLengthOps, q.Operator) {
		if arrSize == 0 || arrSize > maxArrSize {
			return errors.New(ErrorInvalidValuesArrSize)
		} else {
			return nil
		}
	}

	if arrSize != 0 {
		return errors.New(ErrorInvalidValuesArrSize)
	}
	return nil
}

func (q Query) validate() error {
	for i := range q.Values {
		if q.Values[i] == nil {
			return errors.New(ErrorEmptyQueryValue)
		}
	}
	return nil
}

// ValueProof represents a Merkle Proof for a value stored as MT
type ValueProof struct {
	Path  *big.Int
	Value *big.Int
	MTP   *merkletree.Proof
}

func (q ValueProof) validate() error {
	if q.Path == nil {
		return errors.New(ErrorEmptyJsonLDQueryPath)
	}
	if q.Value == nil {
		return errors.New(ErrorEmptyJsonLDQueryValue)
	}
	if q.MTP == nil {
		return errors.New(ErrorEmptyJsonLDQueryProof)
	}
	return nil
}
