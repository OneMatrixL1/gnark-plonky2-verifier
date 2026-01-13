package fri

import (
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"os"

	"github.com/consensys/gnark-crypto/field/goldilocks"
	"github.com/consensys/gnark/frontend"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
)

type Chip struct {
	api               frontend.API             `gnark:"-"`
	gl                *gl.Chip                 `gnark:"-"`
	poseidonBN254Chip *poseidon.BN254Chip      `gnark:"-"`
	poseidonGLChip    *poseidon.GoldilocksChip `gnark:"-"`
	commonData        *types.CommonCircuitData `gnark:"-"`
	friParams         *types.FriParams         `gnark:"-"`
	hashMode          types.HashMode           `gnark:"-"`
}

func NewChip(
	api frontend.API,
	commonData *types.CommonCircuitData,
	friParams *types.FriParams,
	hashMode types.HashMode,
) *Chip {
	poseidonBN254Chip := poseidon.NewBN254Chip(api)
	poseidonGLChip := poseidon.NewGoldilocksChip(api)
	return &Chip{
		api:               api,
		poseidonBN254Chip: poseidonBN254Chip,
		poseidonGLChip:    poseidonGLChip,
		commonData:        commonData,
		friParams:         friParams,
		hashMode:          hashMode,
		gl:                gl.New(api),
	}
}

func (f *Chip) GetInstance(zeta gl.QuadraticExtensionVariable) InstanceInfo {
	zetaBatch := BatchInfo{
		Point:       zeta,
		Polynomials: friAllPolys(f.commonData),
	}

	g := gl.PrimitiveRootOfUnity(f.commonData.DegreeBits)
	zetaNext := f.gl.MulExtension(
		gl.NewVariable(g.Uint64()).ToQuadraticExtension(),
		zeta,
	)

	zetaNextBatch := BatchInfo{
		Point:       zetaNext,
		Polynomials: friZSPolys(f.commonData),
	}

	return InstanceInfo{
		Oracles: friOracles(f.commonData),
		Batches: []BatchInfo{zetaBatch, zetaNextBatch},
	}
}

func (f *Chip) ToOpenings(c variables.OpeningSet) Openings {
	values := c.Constants                         // num_constants + 1
	values = append(values, c.PlonkSigmas...)     // num_routed_wires
	values = append(values, c.Wires...)           // num_wires
	values = append(values, c.PlonkZs...)         // num_challenges
	values = append(values, c.PartialProducts...) // num_challenges * num_partial_products
	values = append(values, c.QuotientPolys...)   // num_challenges * quotient_degree_factor

	// Add lookup openings if present (v1.1.0+)
	if len(c.LookupZs) > 0 {
		values = append(values, c.LookupZs...) // num_challenges * num_lookup_polys
	}

	zetaBatch := OpeningBatch{Values: values}

	// Combine PlonkZsNext and LookupZsNext for the zeta_next batch
	zetaNextValues := c.PlonkZsNext
	if len(c.LookupZsNext) > 0 {
		zetaNextValues = append(zetaNextValues, c.LookupZsNext...)
	}
	zetaNextBatch := OpeningBatch{Values: zetaNextValues}

	return Openings{Batches: []OpeningBatch{zetaBatch, zetaNextBatch}}
}

func (f *Chip) assertLeadingZeros(powWitness gl.Variable, friConfig types.FriConfig) {
	// Asserts that powWitness'es big-endian bit representation has at least friConfig.ProofOfWorkBits leading zeros.
	// Note that this is assuming that the Goldilocks field is being used.  Specfically that the
	// field is 64 bits long.
	f.gl.RangeCheckWithMaxBits(powWitness, 64-friConfig.ProofOfWorkBits)
}

func (f *Chip) fromOpeningsAndAlpha(
	openings *Openings,
	alpha gl.QuadraticExtensionVariable,
) []gl.QuadraticExtensionVariable {
	// One reduced opening for all openings evaluated at point Zeta.
	// Another one for all openings evaluated at point Zeta * Omega (which is only PlonkZsNext polynomial)

	reducedOpenings := make([]gl.QuadraticExtensionVariable, 0, 2)
	for _, batch := range openings.Batches {
		reducedOpenings = append(reducedOpenings, f.gl.ReduceWithPowers(batch.Values, alpha))
	}

	return reducedOpenings
}

// selectHash selects between two GoldilocksHashOut based on a bit
// if bit == 1, returns a; otherwise returns b
// bn254HashToChunks converts a BN254 hash (single field element) to 4 u64 chunks
// This matches the Rust serialization which splits 32 bytes into 4×8 bytes
func (f *Chip) bn254HashToChunks(bn254Hash poseidon.BN254HashOut) poseidon.GoldilocksHashOut {
	// Convert BN254 hash to bits
	bits := f.api.ToBinary(bn254Hash, 256)

	// Split into 4 chunks of 64 bits each
	var result poseidon.GoldilocksHashOut
	for i := 0; i < 4; i++ {
		start := i * 64
		end := start + 64
		chunk := bits[start:end]
		result[i] = gl.NewVariable(f.api.FromBinary(chunk...))
	}

	return result
}

// chunksToB N254Hash reconstructs a BN254 hash from 4 u64 chunks
func (f *Chip) chunksToBN254Hash(chunks poseidon.GoldilocksHashOut) poseidon.BN254HashOut {
	// Convert each chunk to 64 bits and combine
	var allBits []frontend.Variable
	for i := 0; i < 4; i++ {
		chunkBits := f.api.ToBinary(chunks[i].Limb, 64)
		allBits = append(allBits, chunkBits...)
	}

	// Reconstruct as BN254 field element
	return f.api.FromBinary(allBits...)
}

func (f *Chip) selectHash(bit frontend.Variable, a, b poseidon.GoldilocksHashOut) poseidon.GoldilocksHashOut {
	var result poseidon.GoldilocksHashOut
	for i := 0; i < 4; i++ {
		result[i] = gl.Variable{Limb: f.api.Select(bit, a[i].Limb, b[i].Limb)}
	}
	return result
}

// lookup2Hash does a 4-way lookup for GoldilocksHashOut based on 2 bits
func (f *Chip) lookup2Hash(b0, b1 frontend.Variable, h0, h1, h2, h3 poseidon.GoldilocksHashOut) poseidon.GoldilocksHashOut {
	var result poseidon.GoldilocksHashOut
	for i := 0; i < 4; i++ {
		result[i] = gl.Variable{Limb: f.api.Lookup2(b0, b1, h0[i].Limb, h1[i].Limb, h2[i].Limb, h3[i].Limb)}
	}
	return result
}

// assertHashEqual asserts two GoldilocksHashOut are equal
func (f *Chip) assertHashEqual(a, b poseidon.GoldilocksHashOut) {
	for i := 0; i < 4; i++ {
		f.gl.AssertIsEqual(a[i], b[i])
	}
}

func (f *Chip) verifyMerkleProofToCapWithCapIndex(
	leafData []gl.Variable,
	leafIndexBits []frontend.Variable,
	capIndexBits []frontend.Variable,
	merkleCap variables.FriMerkleCap,
	proof *variables.FriMerkleProof,
) {
	debugFRIMerkle := os.Getenv("DEBUG_FRI_MERKLE") == "1"
	var currentDigest poseidon.GoldilocksHashOut

	if debugFRIMerkle {
		fmt.Printf("\n=== verifyMerkleProofToCapWithCapIndex ===\n")
		fmt.Printf("leafData length: %d\n", len(leafData))
		fmt.Printf("Number of siblings: %d\n", len(proof.Siblings))
		fmt.Printf("hashMode: %v\n", f.hashMode)
	}

	// Use hash mode to determine which Poseidon implementation to use
	if f.hashMode == types.HashModePoseidonBN254 {
		// In BN254 mode, hash the leafData using BN254 Poseidon, then convert to 4 u64 chunks
		// leafData contains Goldilocks evaluations, NOT a pre-computed hash
		bn254Hash := f.poseidonBN254Chip.HashOrNoop(leafData)
		currentDigest = f.bn254HashToChunks(bn254Hash)
		if debugFRIMerkle {
			fmt.Printf("Initial leaf hash (BN254 mode, 4 chunks): [%v, %v, %v, %v]\n",
				currentDigest[0].Limb, currentDigest[1].Limb, currentDigest[2].Limb, currentDigest[3].Limb)
		}
	} else {
		// Use Goldilocks Poseidon (emulated, ~5000 constraints/hash)
		currentDigest = f.poseidonGLChip.HashOrNoop(leafData)
	}

	for i, sibling := range proof.Siblings {
		bit := leafIndexBits[i]

		if debugFRIMerkle {
			fmt.Printf("\n--- Merkle step %d ---\n", i)
			fmt.Printf("  leafIndexBit[%d] = %v\n", i, bit)
			fmt.Printf("  sibling[%d]: [%v, %v, %v, %v]\n", i,
				sibling[0].Limb, sibling[1].Limb, sibling[2].Limb, sibling[3].Limb)
			fmt.Printf("  current: [%v, %v, %v, %v]\n",
				currentDigest[0].Limb, currentDigest[1].Limb, currentDigest[2].Limb, currentDigest[3].Limb)
		}

		// Select left/right based on bit: if bit=1, current goes right; else current goes left
		left := f.selectHash(bit, sibling, currentDigest)
		right := f.selectHash(bit, currentDigest, sibling)

		if debugFRIMerkle {
			fmt.Printf("  left (after select): [%v, %v, %v, %v]\n",
				left[0].Limb, left[1].Limb, left[2].Limb, left[3].Limb)
			fmt.Printf("  right (after select): [%v, %v, %v, %v]\n",
				right[0].Limb, right[1].Limb, right[2].Limb, right[3].Limb)
		}

		// Hash the two children to get parent
		if f.hashMode == types.HashModePoseidonBN254 {
			// Reconstruct BN254 hashes from chunks
			leftBN254 := f.chunksToBN254Hash(left)
			rightBN254 := f.chunksToBN254Hash(right)
			// Hash the two BN254 values using BN254 TwoToOne
			bn254Hash := f.poseidonBN254Chip.TwoToOne(leftBN254, rightBN254)
			// Convert back to 4 u64 chunks
			currentDigest = f.bn254HashToChunks(bn254Hash)
			if debugFRIMerkle {
				fmt.Printf("  parent (TwoToOne result): [%v, %v, %v, %v]\n",
					currentDigest[0].Limb, currentDigest[1].Limb, currentDigest[2].Limb, currentDigest[3].Limb)
			}
		} else {
			currentDigest = f.poseidonGLChip.TwoToOne(left, right)
		}
	}

	// We assume that the cap_height is 4.  Create two levels of the Lookup2 circuit
	if len(capIndexBits) != 4 || len(merkleCap) != 16 {
		errorMsg, _ := fmt.Printf(
			"capIndexBits length should be 4 and the merkleCap length should be 16.  Actual values (capIndexBits: %d, merkleCap: %d)\n",
			len(capIndexBits),
			len(merkleCap),
		)
		panic(errorMsg)
	}

	const NUM_LEAF_LOOKUPS = 4
	const STRIDE_LENGTH = 4

	var leafLookups [NUM_LEAF_LOOKUPS]poseidon.GoldilocksHashOut
	// First create the "leaf" lookup2 circuits using least significant bits
	for i := 0; i < NUM_LEAF_LOOKUPS; i++ {
		leafLookups[i] = f.lookup2Hash(
			capIndexBits[0], capIndexBits[1],
			merkleCap[i*STRIDE_LENGTH], merkleCap[i*STRIDE_LENGTH+1],
			merkleCap[i*STRIDE_LENGTH+2], merkleCap[i*STRIDE_LENGTH+3],
		)
	}

	// Use the most 2 significant bits for the "root" lookup
	merkleCapEntry := f.lookup2Hash(capIndexBits[2], capIndexBits[3], leafLookups[0], leafLookups[1], leafLookups[2], leafLookups[3])

	if debugFRIMerkle {
		fmt.Printf("\n--- Final comparison ---\n")
		fmt.Printf("  capIndexBits: [%v, %v, %v, %v]\n", capIndexBits[0], capIndexBits[1], capIndexBits[2], capIndexBits[3])
		fmt.Printf("  currentDigest (computed): [%v, %v, %v, %v]\n",
			currentDigest[0].Limb, currentDigest[1].Limb, currentDigest[2].Limb, currentDigest[3].Limb)
		fmt.Printf("  merkleCapEntry (expected): [%v, %v, %v, %v]\n",
			merkleCapEntry[0].Limb, merkleCapEntry[1].Limb, merkleCapEntry[2].Limb, merkleCapEntry[3].Limb)
		fmt.Printf("  First few cap entries:\n")
		for i := 0; i < 4 && i < len(merkleCap); i++ {
			fmt.Printf("    cap[%d]: [%v, %v, %v, %v]\n", i,
				merkleCap[i][0].Limb, merkleCap[i][1].Limb, merkleCap[i][2].Limb, merkleCap[i][3].Limb)
		}
	}

	f.assertHashEqual(currentDigest, merkleCapEntry)
}

func (f *Chip) verifyInitialProof(xIndexBits []frontend.Variable, proof *variables.FriInitialTreeProof, initialMerkleCaps []variables.FriMerkleCap, capIndexBits []frontend.Variable) {
	if len(proof.EvalsProofs) != len(initialMerkleCaps) {
		panic("length of eval proofs in fri proof should equal length of initial merkle caps")
	}

	for i := 0; i < len(initialMerkleCaps); i++ {
		evals := proof.EvalsProofs[i].Elements
		merkleProof := proof.EvalsProofs[i].MerkleProof
		cap := initialMerkleCaps[i]
		f.verifyMerkleProofToCapWithCapIndex(evals, xIndexBits, capIndexBits, cap, &merkleProof)
	}
}

func (f *Chip) expFromBitsConstBase(
	base goldilocks.Element,
	exponentBits []frontend.Variable,
) gl.Variable {
	product := gl.One()
	for i, bit := range exponentBits {
		// If the bit is 1, we multiply product by base^pow.
		// We can arithmetize this as:
		//     product *= 1 + bit (base^pow - 1)
		//     product = (base^pow - 1) product bit + product
		pow := int64(1 << i)
		basePow := goldilocks.NewElement(0)
		basePow.Exp(base, big.NewInt(pow))
		basePowVariable := gl.NewVariable(basePow.Uint64() - 1)
		product = f.gl.Add(
			f.gl.Mul(
				f.gl.Mul(
					basePowVariable,
					product,
				),
				gl.NewVariable(bit),
			),
			product,
		)
	}
	return product
}

func (f *Chip) calculateSubgroupX(
	xIndexBits []frontend.Variable,
	nLog uint64,
) gl.Variable {
	debugEnabled := os.Getenv("DEBUG_FRI_TRACE") != ""

	// Compute x from its index
	// `subgroup_x` is `subgroup[x_index]`, i.e., the actual field element in the domain.
	// OPTIMIZE - Make these as global values
	g := gl.NewVariable(gl.MULTIPLICATIVE_GROUP_GENERATOR.Uint64())
	base := gl.PrimitiveRootOfUnity(nLog)

	// Reverse the bits to match Rust's reverse_bits(x_index, log_n)
	// xIndexBits are in little-endian (LSB first), we need to reverse them
	reversedBits := make([]frontend.Variable, len(xIndexBits))
	for i := 0; i < len(xIndexBits); i++ {
		reversedBits[i] = xIndexBits[len(xIndexBits)-1-i]
	}

	if debugEnabled {
		fmt.Printf("\n  === calculateSubgroupX ===\n")
		fmt.Printf("    nLog: %d\n", nLog)
		fmt.Printf("    g (generator): %d\n", gl.MULTIPLICATIVE_GROUP_GENERATOR.Uint64())
		fmt.Printf("    base (ω_%d): %d\n", 1<<nLog, base.Uint64())
		fmt.Printf("    xIndexBits (original): [")
		for i := 0; i < len(xIndexBits) && i < 10; i++ {
			fmt.Printf("%v", xIndexBits[i])
			if i < len(xIndexBits)-1 && i < 9 {
				fmt.Printf(", ")
			}
		}
		fmt.Printf("]\n")
		fmt.Printf("    reversedBits: [")
		for i := 0; i < len(reversedBits) && i < 10; i++ {
			fmt.Printf("%v", reversedBits[i])
			if i < len(reversedBits)-1 && i < 9 {
				fmt.Printf(", ")
			}
		}
		fmt.Printf("]\n")
	}

	// Use reversed bits to compute base^(reverse_bits(xIndex))
	product := f.expFromBitsConstBase(base, reversedBits)

	if debugEnabled {
		fmt.Printf("    product (base^xIndex): %v\n", product.Limb)
	}

	result := f.gl.Mul(g, product)

	if debugEnabled {
		fmt.Printf("    result (g * product): %v\n", result.Limb)
	}

	return result
}

func (f *Chip) friCombineInitial(
	instance InstanceInfo,
	proof variables.FriInitialTreeProof,
	friAlpha gl.QuadraticExtensionVariable,
	subgroupX_QE gl.QuadraticExtensionVariable,
	precomputedReducedEval []gl.QuadraticExtensionVariable,
) gl.QuadraticExtensionVariable {
	debugEnabled := os.Getenv("DEBUG_FRI_TRACE") != ""
	sum := gl.ZeroExtension()

	if len(instance.Batches) != len(precomputedReducedEval) {
		panic("len(openings) != len(precomputedReducedEval)")
	}

	if debugEnabled {
		fmt.Println("\n  === friCombineInitial ===")
		fmt.Printf("    num batches: %d\n", len(instance.Batches))
		fmt.Printf("    subgroupX_QE: [%v, %v]\n", subgroupX_QE[0].Limb, subgroupX_QE[1].Limb)
	}

	for i := 0; i < len(instance.Batches); i++ {
		batch := instance.Batches[i]
		reducedOpenings := precomputedReducedEval[i]

		point := batch.Point
		evals := make([]gl.QuadraticExtensionVariable, 0)
		for j, polynomial := range batch.Polynomials {
			eval_value := proof.EvalsProofs[polynomial.OracleIndex].Elements[polynomial.PolynomialInfo]
			evals = append(
				evals,
				gl.QuadraticExtensionVariable{
					eval_value,
					gl.Zero(),
				},
			)
			if debugEnabled && i == 0 && j < 5 {
				fmt.Printf("      polynomial[%d]: OracleIndex=%d, PolynomialInfo=%d, Elements[%d]=%v\n",
					j, polynomial.OracleIndex, polynomial.PolynomialInfo, polynomial.PolynomialInfo, eval_value.Limb)
			}
		}

		if debugEnabled && i == 0 {
			fmt.Printf("      First 5 evals:\n")
			for j := 0; j < 5 && j < len(evals); j++ {
				fmt.Printf("        evals[%d]: [%v, %v]\n", j, evals[j][0].Limb, evals[j][1].Limb)
			}
		}

		reducedEvals := f.gl.ReduceWithPowers(evals, friAlpha)
		numerator := f.gl.SubExtension(reducedEvals, reducedOpenings)
		denominator := f.gl.SubExtension(subgroupX_QE, point)
		sum = f.gl.MulExtension(f.gl.ExpExtension(friAlpha, uint64(len(evals))), sum)
		inv, hasInv := f.gl.InverseExtension(denominator)
		f.api.AssertIsEqual(hasInv, frontend.Variable(1))

		if debugEnabled {
			fmt.Printf("    batch[%d]:\n", i)
			fmt.Printf("      point: [%v, %v]\n", point[0].Limb, point[1].Limb)
			fmt.Printf("      num evals: %d\n", len(evals))
			fmt.Printf("      reducedEvals: [%v, %v]\n", reducedEvals[0].Limb, reducedEvals[1].Limb)
			fmt.Printf("      reducedOpenings: [%v, %v]\n", reducedOpenings[0].Limb, reducedOpenings[1].Limb)
			fmt.Printf("      numerator: [%v, %v]\n", numerator[0].Limb, numerator[1].Limb)
			fmt.Printf("      denominator: [%v, %v]\n", denominator[0].Limb, denominator[1].Limb)
			fmt.Printf("      inv: [%v, %v]\n", inv[0].Limb, inv[1].Limb)
		}

		sum = f.gl.MulAddExtension(
			numerator,
			inv,
			sum,
		)

		if debugEnabled {
			fmt.Printf("      sum after batch: [%v, %v]\n", sum[0].Limb, sum[1].Limb)
		}
	}

	return sum
}

func (f *Chip) finalPolyEval(finalPoly variables.PolynomialCoeffs, point gl.QuadraticExtensionVariable) gl.QuadraticExtensionVariable {
	debugEnabled := os.Getenv("DEBUG_FRI_TRACE") != ""
	ret := gl.ZeroExtension()

	if debugEnabled {
		fmt.Printf("\n  === finalPolyEval ===\n")
		fmt.Printf("    point: [%v, %v]\n", point[0].Limb, point[1].Limb)
		fmt.Printf("    num coeffs: %d\n", len(finalPoly.Coeffs))
	}

	for i := len(finalPoly.Coeffs) - 1; i >= 0; i-- {
		ret = f.gl.MulAddExtension(ret, point, finalPoly.Coeffs[i])
		if debugEnabled && i < 3 {
			fmt.Printf("    After coeff[%d]: ret = [%v, %v]\n", i, ret[0].Limb, ret[1].Limb)
		}
	}

	if debugEnabled {
		fmt.Printf("    final result: [%v, %v]\n", ret[0].Limb, ret[1].Limb)
	}

	return ret
}

func (f *Chip) interpolate(
	x gl.QuadraticExtensionVariable,
	xPoints []gl.QuadraticExtensionVariable,
	yPoints []gl.QuadraticExtensionVariable,
	barycentricWeights []gl.QuadraticExtensionVariable,
) gl.QuadraticExtensionVariable {
	if len(xPoints) != len(yPoints) || len(xPoints) != len(barycentricWeights) {
		panic("length of xPoints, yPoints, and barycentricWeights are inconsistent")
	}

	lX := gl.OneExtension()
	for i := 0; i < len(xPoints); i++ {
		lX = f.gl.SubMulExtension(x, xPoints[i], lX)
	}

	sum := gl.ZeroExtension()

	lookupFromPoints := frontend.Variable(1)
	for i := 0; i < len(xPoints); i++ {
		quotient, hasQuotient := f.gl.DivExtension(
			barycentricWeights[i],
			f.gl.SubExtension(
				x,
				xPoints[i],
			),
		)

		lookupFromPoints = f.api.Mul(hasQuotient, lookupFromPoints)

		sum = f.gl.AddExtension(
			f.gl.MulExtension(
				yPoints[i],
				quotient,
			),
			sum,
		)
	}

	interpolation := f.gl.MulExtension(lX, sum)

	lookupVal := gl.ZeroExtension()
	// Now check if x is already within the xPoints
	for i := 0; i < len(xPoints); i++ {
		lookupVal = f.gl.Lookup(
			f.gl.IsZero(f.gl.SubExtension(x, xPoints[i])),
			lookupVal,
			yPoints[i],
		)
	}

	return f.gl.Lookup(lookupFromPoints, lookupVal, interpolation)
}

func (f *Chip) computeEvaluation(
	x gl.Variable,
	xIndexWithinCosetBits []frontend.Variable,
	arityBits uint64,
	evals []gl.QuadraticExtensionVariable,
	beta gl.QuadraticExtensionVariable,
) gl.QuadraticExtensionVariable {
	arity := 1 << arityBits
	if (len(evals)) != arity {
		panic("len(evals) != arity")
	}
	if arityBits > 8 {
		panic("currently assuming that arityBits is <= 8")
	}

	g := gl.PrimitiveRootOfUnity(arityBits)
	gInv := goldilocks.NewElement(0)
	gInv.Exp(g, big.NewInt(int64(arity-1)))

	// The evaluation vector needs to be reordered first.  Permute the evals array such that each
	// element's new index is the bit reverse of it's original index.
	// OPTIMIZE - Since the size of the evals array should be constant (e.g. 2^arityBits),
	//        we can just hard code the permutation.
	permutedEvals := make([]gl.QuadraticExtensionVariable, len(evals))
	for i := uint8(0); i <= uint8(len(evals)-1); i++ {
		newIndex := bits.Reverse8(i) >> (8 - arityBits)
		permutedEvals[newIndex] = evals[i]
	}

	// Want `g^(arity - rev_x_index_within_coset)` as in the out-of-circuit version. Compute it
	// as `(g^-1)^rev_x_index_within_coset`.
	revXIndexWithinCosetBits := make([]frontend.Variable, len(xIndexWithinCosetBits))
	for i := 0; i < len(xIndexWithinCosetBits); i++ {
		revXIndexWithinCosetBits[len(xIndexWithinCosetBits)-1-i] = xIndexWithinCosetBits[i]
	}
	start := f.expFromBitsConstBase(gInv, revXIndexWithinCosetBits)
	cosetStart := f.gl.Mul(start, x)

	xPoints := make([]gl.QuadraticExtensionVariable, len(evals))
	yPoints := permutedEvals

	// OPTIMIZE: Make g_F a constant
	g_F := gl.NewVariable(g.Uint64()).ToQuadraticExtension()
	xPoints[0] = gl.QuadraticExtensionVariable{cosetStart, gl.Zero()}
	for i := 1; i < len(evals); i++ {
		xPoints[i] = f.gl.MulExtension(xPoints[i-1], g_F)
	}

	// OPTIMIZE:  This is n^2.  Is there a way to do this better?
	// Compute the barycentric weights
	barycentricWeights := make([]gl.QuadraticExtensionVariable, len(xPoints))
	for i := 0; i < len(xPoints); i++ {
		barycentricWeights[i] = gl.OneExtension()
		for j := 0; j < len(xPoints); j++ {
			if i != j {
				barycentricWeights[i] = f.gl.SubMulExtension(
					xPoints[i],
					xPoints[j],
					barycentricWeights[i],
				)
			}
		}
		// Take the inverse of the barycentric weights
		// OPTIMIZE: Can provide a witness to this value
		inv, hasInv := f.gl.InverseExtension(barycentricWeights[i])
		f.api.AssertIsEqual(hasInv, frontend.Variable(1))
		barycentricWeights[i] = inv
	}

	return f.interpolate(beta, xPoints, yPoints, barycentricWeights)
}

func (f *Chip) verifyQueryRound(
	instance InstanceInfo,
	challenges *variables.FriChallenges,
	precomputedReducedEval []gl.QuadraticExtensionVariable,
	initialMerkleCaps []variables.FriMerkleCap,
	proof *variables.FriProof,
	xIndex gl.Variable,
	n uint64,
	nLog uint64,
	roundProof *variables.FriQueryRound,
) {
	debugEnabled := os.Getenv("DEBUG_FRI_TRACE") != ""

	if debugEnabled {
		fmt.Println("\n=== FRI verifyQueryRound ===")
		fmt.Printf("  xIndex (raw): %v\n", xIndex.Limb)
		fmt.Printf("  n: %d, nLog: %d\n", n, nLog)
		fmt.Printf("  Number of reduction_arity_bits: %d\n", len(f.friParams.ReductionArityBits))
		fmt.Printf("  Reduction arity bits: %v\n", f.friParams.ReductionArityBits)
	}

	// Note assertNoncanonicalIndicesOK does not add any constraints, it's a sanity check on the config
	assertNoncanonicalIndicesOK(*f.friParams)

	xIndex = f.gl.Reduce(xIndex)
	xIndexBits := f.api.ToBinary(xIndex.Limb, 64)[0 : f.friParams.DegreeBits+f.friParams.Config.RateBits]
	capIndexBits := xIndexBits[len(xIndexBits)-int(f.friParams.Config.CapHeight):]

	if debugEnabled {
		fmt.Printf("  xIndex (after reduce): %v\n", xIndex.Limb)
		fmt.Printf("  xIndexBits length: %d (degreeBits=%d + rateBits=%d)\n",
			len(xIndexBits), f.friParams.DegreeBits, f.friParams.Config.RateBits)
		// Print the first few bits
		fmt.Printf("  xIndexBits (first 5): [")
		for i := 0; i < 5 && i < len(xIndexBits); i++ {
			fmt.Printf("%v", xIndexBits[i])
			if i < 4 {
				fmt.Printf(", ")
			}
		}
		fmt.Printf("]\n")
		fmt.Printf("  capHeight: %d, capIndexBits length: %d\n",
			f.friParams.Config.CapHeight, len(capIndexBits))
	}

	f.verifyInitialProof(xIndexBits, &roundProof.InitialTreesProof, initialMerkleCaps, capIndexBits)

	subgroupX := f.calculateSubgroupX(
		xIndexBits,
		nLog,
	)

	if debugEnabled {
		fmt.Printf("  subgroupX (calculated from xIndexBits): %v\n", subgroupX.Limb)
	}

	subgroupX_QE := subgroupX.ToQuadraticExtension()

	if debugEnabled {
		fmt.Printf("  subgroupX_QE: [%v, %v]\n", subgroupX_QE[0].Limb, subgroupX_QE[1].Limb)
		fmt.Printf("  FriAlpha: [%v, %v]\n", challenges.FriAlpha[0].Limb, challenges.FriAlpha[1].Limb)
	}

	oldEval := f.friCombineInitial(
		instance,
		roundProof.InitialTreesProof,
		challenges.FriAlpha,
		subgroupX_QE,
		precomputedReducedEval,
	)

	if debugEnabled {
		fmt.Printf("  Initial oldEval (after friCombineInitial): [%v, %v]\n", oldEval[0].Limb, oldEval[1].Limb)
		fmt.Printf("  Number of FRI rounds: %d\n", len(f.friParams.ReductionArityBits))
	}

	for i, arityBits := range f.friParams.ReductionArityBits {
		evals := roundProof.Steps[i].Evals

		cosetIndexBits := xIndexBits[arityBits:]
		xIndexWithinCosetBits := xIndexBits[:arityBits]

		// Assumes that the arity bits will be 4.  That means that the range of
		// xIndexWithCoset is [0,2^4-1].  This is based on plonky2's circuit recursive
		// config:  https://github.com/mir-protocol/plonky2/blob/main/plonky2/src/plonk/circuit_data.rs#L63
		// Will use a two levels tree of 4-selector gadgets.
		if arityBits != 4 {
			panic("assuming arity bits is 4")
		}

		const NUM_LEAF_LOOKUPS = 4
		var leafLookups [NUM_LEAF_LOOKUPS]gl.QuadraticExtensionVariable
		// First create the "leaf" lookup2 circuits
		// The will use the least significant bits of the xIndexWithCosetBits array
		for i := 0; i < NUM_LEAF_LOOKUPS; i++ {
			leafLookups[i] = f.gl.Lookup2(
				xIndexWithinCosetBits[0],
				xIndexWithinCosetBits[1],
				evals[i*NUM_LEAF_LOOKUPS],
				evals[i*NUM_LEAF_LOOKUPS+1],
				evals[i*NUM_LEAF_LOOKUPS+2],
				evals[i*NUM_LEAF_LOOKUPS+3],
			)
		}

		// Use the most 2 significant bits of the xIndexWithCosetBits array for the "root" lookup
		newEval := f.gl.Lookup2(
			xIndexWithinCosetBits[2],
			xIndexWithinCosetBits[3],
			leafLookups[0],
			leafLookups[1],
			leafLookups[2],
			leafLookups[3],
		)

		f.gl.AssertIsEqual(newEval[0], oldEval[0])
		f.gl.AssertIsEqual(newEval[1], oldEval[1])

		oldEval = f.computeEvaluation(
			subgroupX,
			xIndexWithinCosetBits,
			arityBits,
			evals,
			challenges.FriBetas[i],
		)

		if debugEnabled {
			fmt.Printf("  After FRI round %d (arityBits=%d): oldEval = [%v, %v]\n", i, arityBits, oldEval[0].Limb, oldEval[1].Limb)
		}

		// Convert evals (array of QE) to fields by taking their 0th degree coefficients
		fieldEvals := make([]gl.Variable, 0, 2*len(evals))
		for j := 0; j < len(evals); j++ {
			fieldEvals = append(fieldEvals, evals[j][0])
			fieldEvals = append(fieldEvals, evals[j][1])
		}
		f.verifyMerkleProofToCapWithCapIndex(
			fieldEvals,
			cosetIndexBits,
			capIndexBits,
			proof.CommitPhaseMerkleCaps[i],
			&roundProof.Steps[i].MerkleProof,
		)

		// Update the point x to x^arity.
		for j := uint64(0); j < arityBits; j++ {
			subgroupX = f.gl.Mul(subgroupX, subgroupX)
		}

		xIndexBits = cosetIndexBits
	}

	subgroupX_QE = subgroupX.ToQuadraticExtension()
	finalPolyEval := f.finalPolyEval(proof.FinalPoly, subgroupX_QE)

	if debugEnabled {
		fmt.Println("\n  Final Check:")
		fmt.Printf("    subgroupX: %v\n", subgroupX.Limb)
		fmt.Printf("    subgroupX_QE: [%v, %v]\n", subgroupX_QE[0].Limb, subgroupX_QE[1].Limb)
		fmt.Printf("    oldEval (computed): [%v, %v]\n", oldEval[0].Limb, oldEval[1].Limb)
		fmt.Printf("    finalPolyEval (expected): [%v, %v]\n", finalPolyEval[0].Limb, finalPolyEval[1].Limb)
		fmt.Printf("    finalPoly coeffs: %d coefficients\n", len(proof.FinalPoly.Coeffs))
		for i, coeff := range proof.FinalPoly.Coeffs {
			fmt.Printf("      coeff[%d]: [%v, %v]\n", i, coeff[0].Limb, coeff[1].Limb)
		}
	}

	f.gl.AssertIsEqual(oldEval[0], finalPolyEval[0])
	f.gl.AssertIsEqual(oldEval[1], finalPolyEval[1])
}

func (f *Chip) VerifyFriProof(
	instance InstanceInfo,
	openings Openings,
	friChallenges *variables.FriChallenges,
	initialMerkleCaps []variables.FriMerkleCap,
	friProof *variables.FriProof,
) {
	// Not adding any constraints but a sanity check on the proof shape matching the friParams (constant).
	validateFriProofShape(friProof, instance, f.friParams)

	// Check POW
	f.assertLeadingZeros(friChallenges.FriPowResponse, f.friParams.Config)

	// Check that parameters are coherent. Not adding any constraints but a sanity check
	// on the proof shape matching the friParams.
	if int(f.friParams.Config.NumQueryRounds) != len(friProof.QueryRoundProofs) {
		panic("Number of query rounds does not match config.")
	}

	precomputedReducedEvals := f.fromOpeningsAndAlpha(&openings, friChallenges.FriAlpha)

	// Size of the LDE domain.
	nLog := f.friParams.DegreeBits + f.friParams.Config.RateBits
	n := uint64(math.Pow(2, float64(nLog)))

	if len(friChallenges.FriQueryIndices) != len(friProof.QueryRoundProofs) {
		panic(fmt.Sprintf(
			"Number of query indices (%d) should equal number of query round proofs (%d)",
			len(friChallenges.FriQueryIndices),
			len(friProof.QueryRoundProofs),
		))
	}

	for idx, xIndex := range friChallenges.FriQueryIndices {
		roundProof := friProof.QueryRoundProofs[idx]

		f.verifyQueryRound(
			instance,
			friChallenges,
			precomputedReducedEvals,
			initialMerkleCaps,
			friProof,
			xIndex,
			n,
			nLog,
			&roundProof,
		)
	}
}
