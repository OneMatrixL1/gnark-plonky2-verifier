package types

import (
	"github.com/succinctlabs/gnark-plonky2-verifier/plonk/gates"
)

// ReductionStrategyType represents the FRI reduction strategy enum
type ReductionStrategyType int

const (
	ReductionStrategyFixed ReductionStrategyType = iota
	ReductionStrategyConstantArityBits
	ReductionStrategyMinSize
)

// ReductionStrategy represents the FRI reduction strategy with its parameters
type ReductionStrategy struct {
	Type          ReductionStrategyType
	ArityBits     uint64   // For ConstantArityBits: the arity
	FinalPolyBits uint64   // For ConstantArityBits: final poly bits
	MaxArityBits  uint64   // For MinSize: optional max arity
	Fixed         []uint64 // For Fixed: the exact arity sequence
}

// Serialize returns the serialized form of the reduction strategy as used in challenger
// - Fixed: [0, ...arity_bits]
// - ConstantArityBits: [1, arity_bits, final_poly_bits]
// - MinSize: [2, max_arity_bits]
func (r *ReductionStrategy) Serialize() []uint64 {
	switch r.Type {
	case ReductionStrategyFixed:
		result := []uint64{0}
		result = append(result, r.Fixed...)
		return result
	case ReductionStrategyConstantArityBits:
		return []uint64{1, r.ArityBits, r.FinalPolyBits}
	case ReductionStrategyMinSize:
		return []uint64{2, r.MaxArityBits}
	default:
		panic("unknown reduction strategy type")
	}
}

type FriConfig struct {
	RateBits        uint64
	CapHeight       uint64
	ProofOfWorkBits uint64
	NumQueryRounds  uint64
}

func (fc *FriConfig) Rate() float64 {
	return 1.0 / float64((uint64(1) << fc.RateBits))
}

type FriParams struct {
	Config             FriConfig
	Hiding             bool
	DegreeBits         uint64
	ReductionArityBits []uint64
}

func (p *FriParams) TotalArities() int {
	res := 0
	for _, b := range p.ReductionArityBits {
		res += int(b)
	}
	return res
}

func (p *FriParams) MaxArityBits() int {
	res := 0
	for _, b := range p.ReductionArityBits {
		if int(b) > res {
			res = int(b)
		}
	}
	return res
}

func (p *FriParams) LdeBits() int {
	return int(p.DegreeBits + p.Config.RateBits)
}

func (p *FriParams) LdeSize() int {
	return 1 << p.LdeBits()
}

func (p *FriParams) FinalPolyBits() int {
	return int(p.DegreeBits) - p.TotalArities()
}

func (p *FriParams) FinalPolyLen() int {
	return int(1 << p.FinalPolyBits())
}

type CircuitConfig struct {
	NumWires                uint64
	NumRoutedWires          uint64
	NumConstants            uint64
	UseBaseArithmeticGate   bool
	SecurityBits            uint64
	NumChallenges           uint64
	ZeroKnowledge           bool
	MaxQuotientDegreeFactor uint64
	FriConfig               FriConfig
}

type CommonCircuitData struct {
	Config CircuitConfig
	FriParams
	ReductionStrategy    ReductionStrategy // Needed for challenger FRI params observation
	GateIds              []string
	SelectorsInfo        gates.SelectorsInfo
	DegreeBits           uint64
	QuotientDegreeFactor uint64
	NumGateConstraints   uint64
	NumConstants         uint64
	NumPublicInputs      uint64
	KIs                  []uint64
	NumPartialProducts   uint64
	NumLookupPolys       uint64 // For lookups (v1.1.0+)
	NumLookupSelectors   uint64 // For lookups (v1.1.0+)
	Luts                 []any  // Placeholder storage for LUT metadata
}
