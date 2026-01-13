package challenger

import (
	"fmt"
	"log"
	"os"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/fri"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
)

var debugBN254Trace = os.Getenv("DEBUG_BN254_TRACE") == "1"
var debugChallengerState = os.Getenv("DEBUG_CHALLENGER_STATE") == "1"

type Chip struct {
	api               frontend.API `gnark:"-"`
	poseidonChip      *poseidon.GoldilocksChip
	poseidonBN254Chip *poseidon.BN254Chip
	spongeState       poseidon.GoldilocksState
	inputBuffer       []gl.Variable
	outputBuffer      []gl.Variable
	hashMode          types.HashMode `gnark:"-"`
}

func NewChip(api frontend.API, hashMode types.HashMode) *Chip {
	var spongeState poseidon.GoldilocksState
	var inputBuffer []gl.Variable
	var outputBuffer []gl.Variable
	for i := 0; i < poseidon.SPONGE_WIDTH; i++ {
		spongeState[i] = gl.Zero()
	}
	poseidonChip := poseidon.NewGoldilocksChip(api)
	poseidonBN254Chip := poseidon.NewBN254Chip(api)
	return &Chip{
		api:               api,
		poseidonChip:      poseidonChip,
		poseidonBN254Chip: poseidonBN254Chip,
		spongeState:       spongeState,
		inputBuffer:       inputBuffer,
		outputBuffer:      outputBuffer,
		hashMode:          hashMode,
	}
}

func (c *Chip) ObserveElement(element gl.Variable) {
	// Clear the output buffer
	c.outputBuffer = make([]gl.Variable, 0)
	c.inputBuffer = append(c.inputBuffer, element)
	if len(c.inputBuffer) == poseidon.SPONGE_RATE {
		c.duplexing()
	}
}

// ObserveFriParams observes the FRI parameters for Fiat-Shamir.
// This must be called before observing circuit_digest in get_challenges.
// The observation order matches Rust's FriParams::observe:
//  1. FriConfig: rate_bits, cap_height, proof_of_work_bits, reduction_strategy.serialize(), num_query_rounds
//  2. hiding (bool as 0 or 1)
//  3. degree_bits
//  4. reduction_arity_bits (as elements)
func (c *Chip) ObserveFriParams(friParams types.FriParams, friConfig types.FriConfig, reductionStrategy types.ReductionStrategy) {
	debugEnabled := os.Getenv("DEBUG_BN254_TRACE") != ""

	if debugEnabled {
		fmt.Println("\nObserving FRI params:")
	}

	// Observe FriConfig fields
	if debugEnabled {
		fmt.Printf("  1. rate_bits = %d\n", friConfig.RateBits)
	}
	c.ObserveElement(gl.NewVariable(friConfig.RateBits))

	if debugEnabled {
		fmt.Printf("  2. cap_height = %d\n", friConfig.CapHeight)
	}
	c.ObserveElement(gl.NewVariable(friConfig.CapHeight))

	if debugEnabled {
		fmt.Printf("  3. proof_of_work_bits = %d\n", friConfig.ProofOfWorkBits)
	}
	c.ObserveElement(gl.NewVariable(uint64(friConfig.ProofOfWorkBits)))

	// Observe reduction_strategy.serialize()
	// Format depends on strategy type:
	// - Fixed: [0, ...arity_bits]
	// - ConstantArityBits: [1, arity_bits, final_poly_bits]
	// - MinSize: [2, max_arity_bits]
	strategyElements := reductionStrategy.Serialize()
	if debugEnabled {
		// Determine strategy type from first element
		if len(strategyElements) > 0 {
			strategyType := strategyElements[0]
			var strategyName string
			switch strategyType {
			case 0:
				strategyName = "Fixed"
			case 1:
				strategyName = "ConstantArityBits"
			case 2:
				strategyName = "MinSize"
			default:
				strategyName = "Unknown"
			}
			fmt.Printf("  4. reduction_strategy type = %d (%s)\n", strategyType, strategyName)

			// Print additional strategy fields
			for i := 1; i < len(strategyElements); i++ {
				var fieldName string
				if strategyType == 1 { // ConstantArityBits
					if i == 1 {
						fieldName = "arity_bits"
					} else if i == 2 {
						fieldName = "final_poly_bits"
					}
				}
				fmt.Printf("  %d. reduction_strategy %s = %d\n", i+4, fieldName, strategyElements[i])
			}
		}
	}
	for _, elem := range strategyElements {
		c.ObserveElement(gl.NewVariable(elem))
	}

	if debugEnabled {
		fmt.Printf("  7. num_query_rounds = %d\n", friConfig.NumQueryRounds)
	}
	c.ObserveElement(gl.NewVariable(friConfig.NumQueryRounds))

	// Observe FriParams fields
	var hidingValue uint64 = 0
	if friParams.Hiding {
		hidingValue = 1
	}
	if debugEnabled {
		fmt.Printf("  8. hiding = %d\n", hidingValue)
	}
	c.ObserveElement(gl.NewVariable(hidingValue))

	if debugEnabled {
		fmt.Printf("  9. degree_bits = %d\n", friParams.DegreeBits)
	}
	c.ObserveElement(gl.NewVariable(friParams.DegreeBits))

	// Observe reduction_arity_bits
	if debugEnabled && len(friParams.ReductionArityBits) > 0 {
		fmt.Println("  10+. reduction_arity_bits:")
		for i, arityBits := range friParams.ReductionArityBits {
			fmt.Printf("    [%d] = %d\n", i, arityBits)
		}
	}
	for _, arityBits := range friParams.ReductionArityBits {
		c.ObserveElement(gl.NewVariable(arityBits))
	}

	if debugEnabled {
		fmt.Println("\n✅ FRI params observed")
	}
}

func (c *Chip) ObserveElements(elements []gl.Variable) {
	for i := 0; i < len(elements); i++ {
		c.ObserveElement(elements[i])
	}
}

func (c *Chip) ObserveHash(hash poseidon.GoldilocksHashOut) {
	if debugChallengerState {
		fmt.Printf("[CHALLENGER] Before ObserveHash: spongeState[0:4]=[%v,%v,%v,%v]\n",
			c.spongeState[0].Limb, c.spongeState[1].Limb, c.spongeState[2].Limb, c.spongeState[3].Limb)
		fmt.Printf("[CHALLENGER] Observing hash: [%v,%v,%v,%v]\n",
			hash[0].Limb, hash[1].Limb, hash[2].Limb, hash[3].Limb)
	}
	elements := c.poseidonChip.ToVec(hash)
	c.ObserveElements(elements)
	if debugChallengerState {
		fmt.Printf("[CHALLENGER] After ObserveHash: spongeState[0:4]=[%v,%v,%v,%v]\n",
			c.spongeState[0].Limb, c.spongeState[1].Limb, c.spongeState[2].Limb, c.spongeState[3].Limb)
	}
}

func (c *Chip) ObserveBN254Hash(hash poseidon.BN254HashOut) {
	elements := c.poseidonBN254Chip.ToVec(hash)
	c.ObserveElements(elements)
}

// ObserveHashFromChunks observes a hash that's stored as 4 u64 chunks (BN254 mode wire format)
// Reconstructs the BN254 field element and observes it properly
func (c *Chip) ObserveHashFromChunks(chunks poseidon.GoldilocksHashOut) {
	log.Println("[ObserveHashFromChunks] CALLED - Converting 4 chunks to BN254 to 5 Goldilocks elements")

	// Reconstruct BN254 field element from 4 u64 chunks
	var allBits []frontend.Variable
	for i := 0; i < 4; i++ {
		chunkBits := c.api.ToBinary(chunks[i].Limb, 64)
		allBits = append(allBits, chunkBits...)
	}

	bn254Hash := c.api.FromBinary(allBits...)
	c.ObserveBN254Hash(bn254Hash)

	log.Println("[ObserveHashFromChunks] DONE - BN254 hash observed via ToVec (should be 5 elements)")
}

func (c *Chip) ObserveCap(cap []poseidon.GoldilocksHashOut) {
	for i := 0; i < len(cap); i++ {
		if debugBN254Trace {
			fmt.Printf("ObserveCap[%d]: %v\n", i, cap[i])
		}
		c.ObserveHash(cap[i])
	}
}

func (c *Chip) ObserveCapBN254(cap []poseidon.GoldilocksHashOut) {
	for i := 0; i < len(cap); i++ {
		c.ObserveHashFromChunks(cap[i])
	}
}

func (c *Chip) ObserveExtensionElement(element gl.QuadraticExtensionVariable) {
	c.ObserveElements(element[:])
}

func (c *Chip) ObserveExtensionElements(elements []gl.QuadraticExtensionVariable) {
	for i := 0; i < len(elements); i++ {
		c.ObserveExtensionElement(elements[i])
	}
}

func (c *Chip) ObserveOpenings(openings fri.Openings) {
	for i := 0; i < len(openings.Batches); i++ {
		c.ObserveExtensionElements(openings.Batches[i].Values)
	}
}

func (c *Chip) GetChallenge() gl.Variable {
	if len(c.inputBuffer) != 0 || len(c.outputBuffer) == 0 {
		c.duplexing()
	}

	challenge := c.outputBuffer[len(c.outputBuffer)-1]
	c.outputBuffer = c.outputBuffer[:len(c.outputBuffer)-1]

	return challenge
}

func (c *Chip) GetNChallenges(n uint64) []gl.Variable {
	challenges := make([]gl.Variable, n)
	for i := uint64(0); i < n; i++ {
		challenges[i] = c.GetChallenge()
	}
	return challenges
}

func (c *Chip) GetExtensionChallenge() gl.QuadraticExtensionVariable {
	if debugChallengerState {
		fmt.Printf("[CHALLENGER] Before GetExtensionChallenge: spongeState[0:4]=[%v,%v,%v,%v]\n",
			c.spongeState[0].Limb, c.spongeState[1].Limb, c.spongeState[2].Limb, c.spongeState[3].Limb)
		fmt.Printf("[CHALLENGER] outputBuffer len=%d\n", len(c.outputBuffer))
	}
	values := c.GetNChallenges(2)
	if debugChallengerState {
		fmt.Printf("[CHALLENGER] After GetExtensionChallenge: result=[%v,%v]\n", values[0].Limb, values[1].Limb)
		fmt.Printf("[CHALLENGER] After GetExtensionChallenge: spongeState[0:4]=[%v,%v,%v,%v]\n",
			c.spongeState[0].Limb, c.spongeState[1].Limb, c.spongeState[2].Limb, c.spongeState[3].Limb)
	}
	return gl.QuadraticExtensionVariable{values[0], values[1]}
}

func (c *Chip) GetHash() poseidon.GoldilocksHashOut {
	return [poseidon.POSEIDON_GL_HASH_SIZE]gl.Variable{c.GetChallenge(), c.GetChallenge(), c.GetChallenge(), c.GetChallenge()}
}

func (c *Chip) GetFriChallenges(
	commitPhaseMerkleCaps []variables.FriMerkleCap,
	finalPoly variables.PolynomialCoeffs,
	powWitness gl.Variable,
	config types.FriConfig,
	degreeBits uint64,
) variables.FriChallenges {
	numFriQueries := config.NumQueryRounds
	friAlpha := c.GetExtensionChallenge()

	var friBetas []gl.QuadraticExtensionVariable
	for i := 0; i < len(commitPhaseMerkleCaps); i++ {
		// Use BN254 mode observation if hash mode is BN254
		if c.hashMode == types.HashModePoseidonBN254 {
			c.ObserveCapBN254(commitPhaseMerkleCaps[i])
		} else {
			c.ObserveCap(commitPhaseMerkleCaps[i])
		}
		friBetas = append(friBetas, c.GetExtensionChallenge())
	}

	c.ObserveExtensionElements(finalPoly.Coeffs)
	c.ObserveElement(powWitness)

	friPowResponse := c.GetChallenge()
	friQueryIndices := c.GetNChallenges(numFriQueries)

	return variables.FriChallenges{
		FriAlpha:        friAlpha,
		FriBetas:        friBetas,
		FriPowResponse:  friPowResponse,
		FriQueryIndices: friQueryIndices,
	}
}

func (c *Chip) duplexing() {
	if len(c.inputBuffer) > poseidon.SPONGE_RATE {
		fmt.Println(len(c.inputBuffer))
		panic("something went wrong")
	}

	glApi := gl.New(c.api)

	for i := 0; i < len(c.inputBuffer); i++ {
		c.spongeState[i] = glApi.Reduce(c.inputBuffer[i])
	}
	// Clear the input buffer
	c.inputBuffer = make([]gl.Variable, 0)
	c.spongeState = c.poseidonChip.Poseidon(c.spongeState)

	// Clear the output buffer
	c.outputBuffer = make([]gl.Variable, 0)
	for i := 0; i < poseidon.SPONGE_RATE; i++ {
		c.outputBuffer = append(c.outputBuffer, c.spongeState[i])
	}
}
