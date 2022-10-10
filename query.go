package circuits

import (
	"math/big"

	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-schema-processor/merklize"
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
)

// Query represents basic request to claim slot verification
type Query struct {
	SlotIndex int
	Values    []*big.Int
	Operator  int
}

// QueryOperators represents operators for atomic circuits
var QueryOperators = map[string]int{
	"$noop": NOOP,
	"$eq":   EQ,
	"$lt":   LT,
	"$gt":   GT,
	"$in":   IN,
	"$nin":  NIN,
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
	case EQ:
		return s.x.Cmp(s.y) == 0, nil
	case LT:
		return s.x.Cmp(s.y) == -1, nil
	case GT:
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
	}
	return false, errors.New("unknown compare type for vector")
}

// FactoryComparer depends on input data will return right comparer.
func FactoryComparer(x *big.Int, y []*big.Int, t int) (Comparer, error) {
	var cmp Comparer
	switch t {
	case EQ, LT, GT:
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

// JsonLDQuery represents basic request to Json-LD claim field
type JsonLDQuery struct {
	Path     merklize.Path
	Value    *big.Int
	MTP      *merkletree.Proof
	Operator int
	Values   []*big.Int
}

func (q JsonLDQuery) validate() error {
	if q.Values == nil {
		return errors.New(ErrorEmptyJsonLDQueryValue)
	}
	if q.MTP == nil {
		return errors.New(ErrorEmptyJsonLDQueryProof)
	}
	for i := range q.Values {
		if q.Values[i] == nil {
			return errors.New(ErrorEmptyJsonLDQueryValues)
		}
	}
	return nil
}
