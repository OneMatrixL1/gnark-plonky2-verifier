package plonk

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/plonk/gates"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
)

type PlonkChip struct {
	api frontend.API `gnark:"-"`

	commonData types.CommonCircuitData `gnark:"-"`

	// These are global constant variables that we use in this Chip that we save here.
	// This avoids having to recreate them every time we use them.
	DEGREE        gl.Variable                   `gnark:"-"`
	DEGREE_BITS_F gl.Variable                   `gnark:"-"`
	DEGREE_QE     gl.QuadraticExtensionVariable `gnark:"-"`
	commonDataKIs []gl.Variable                 `gnark:"-"`

	evaluateGatesChip *gates.EvaluateGatesChip
}

func NewPlonkChip(api frontend.API, commonData types.CommonCircuitData) *PlonkChip {
	// Create the gates based on commonData GateIds
	createdGates := []gates.Gate{}
	for _, gateId := range commonData.GateIds {
		createdGates = append(createdGates, gates.GateInstanceFromId(gateId))
	}

	evaluateGatesChip := gates.NewEvaluateGatesChip(
		api,
		createdGates,
		commonData.NumGateConstraints,
		commonData.NumLookupSelectors,
		commonData.SelectorsInfo,
	)

	return &PlonkChip{
		api: api,

		commonData: commonData,

		DEGREE:        gl.NewVariable(1 << commonData.DegreeBits),
		DEGREE_BITS_F: gl.NewVariable(commonData.DegreeBits),
		DEGREE_QE:     gl.NewVariable(1 << commonData.DegreeBits).ToQuadraticExtension(),
		commonDataKIs: gl.Uint64ArrayToVariableArray(commonData.KIs),

		evaluateGatesChip: evaluateGatesChip,
	}
}

func (p *PlonkChip) expPowerOf2Extension(x gl.QuadraticExtensionVariable) gl.QuadraticExtensionVariable {
	glApi := gl.New(p.api)
	fmt.Printf("[DEBUG expPowerOf2Extension] Input x = [%v, %v]\n", x[0].Limb, x[1].Limb)
	fmt.Printf("[DEBUG expPowerOf2Extension] DegreeBits = %d (will square %d times)\n", p.commonData.DegreeBits, p.commonData.DegreeBits)
	for i := uint64(0); i < p.commonData.DegreeBits; i++ {
		oldX := x
		x = glApi.MulExtension(x, x)
		fmt.Printf("[DEBUG expPowerOf2Extension] Iteration %d: [%v,%v]^2 = [%v,%v]\n",
			i, oldX[0].Limb, oldX[1].Limb, x[0].Limb, x[1].Limb)
	}
	fmt.Printf("[DEBUG expPowerOf2Extension] Final result = [%v, %v]\n", x[0].Limb, x[1].Limb)
	return x
}

func (p *PlonkChip) evalL0(x gl.QuadraticExtensionVariable, xPowN gl.QuadraticExtensionVariable) gl.QuadraticExtensionVariable {
	// L_0(x) = (x^n - 1) / (n * (x - 1))
	glApi := gl.New(p.api)

	fmt.Printf("\n[DEBUG evalL0] ═══════════════════════════════════════════════════════════\n")
	fmt.Printf("[DEBUG evalL0] Computing L_0(x) = (x^n - 1) / (n * (x - 1))\n")
	fmt.Printf("[DEBUG evalL0] ═══════════════════════════════════════════════════════════\n")
	fmt.Printf("[DEBUG evalL0] Input x (zeta) = [%v, %v]\n", x[0].Limb, x[1].Limb)
	fmt.Printf("[DEBUG evalL0] Input x^n = [%v, %v]\n", xPowN[0].Limb, xPowN[1].Limb)
	fmt.Printf("[DEBUG evalL0] DEGREE (n) = %v\n", p.DEGREE.Limb)

	// Step 1: x^n - 1
	evalZeroPoly := glApi.SubExtension(
		xPowN,
		gl.OneExtension(),
	)
	fmt.Printf("[DEBUG evalL0] STEP 1: Numerator = x^n - 1\n")
	fmt.Printf("[DEBUG evalL0]   x^n = [%v, %v]\n", xPowN[0].Limb, xPowN[1].Limb)
	fmt.Printf("[DEBUG evalL0]   1 = [1, 0]\n")
	fmt.Printf("[DEBUG evalL0]   numerator = [%v, %v]\n", evalZeroPoly[0].Limb, evalZeroPoly[1].Limb)

	// Step 2: n * x
	nTimesX := glApi.ScalarMulExtension(x, p.DEGREE)
	fmt.Printf("[DEBUG evalL0] STEP 2: Calculate n * x\n")
	fmt.Printf("[DEBUG evalL0]   n = %v\n", p.DEGREE.Limb)
	fmt.Printf("[DEBUG evalL0]   x = [%v, %v]\n", x[0].Limb, x[1].Limb)
	fmt.Printf("[DEBUG evalL0]   n * x = [%v, %v]\n", nTimesX[0].Limb, nTimesX[1].Limb)

	// Step 3: n * (x - 1) = n*x - n
	fmt.Printf("[DEBUG evalL0] STEP 3: Calculate denominator = n * (x - 1) = n*x - n\n")
	fmt.Printf("[DEBUG evalL0]   n*x = [%v, %v]\n", nTimesX[0].Limb, nTimesX[1].Limb)
	fmt.Printf("[DEBUG evalL0]   DEGREE_QE (n as extension) = [%v, %v]\n", p.DEGREE_QE[0].Limb, p.DEGREE_QE[1].Limb)

	denominator := glApi.SubExtension(
		nTimesX,
		p.DEGREE_QE,
	)
	fmt.Printf("[DEBUG evalL0]   denominator (n*x - n) = [%v, %v]\n", denominator[0].Limb, denominator[1].Limb)

	// Step 4: Division
	fmt.Printf("[DEBUG evalL0] STEP 4: Division = numerator / denominator\n")
	fmt.Printf("[DEBUG evalL0]   numerator = [%v, %v]\n", evalZeroPoly[0].Limb, evalZeroPoly[1].Limb)
	fmt.Printf("[DEBUG evalL0]   denominator = [%v, %v]\n", denominator[0].Limb, denominator[1].Limb)

	quotient, hasQuotient := glApi.DivExtension(
		evalZeroPoly,
		denominator,
	)
	fmt.Printf("[DEBUG evalL0]   L_0(x) = [%v, %v]\n", quotient[0].Limb, quotient[1].Limb)
	fmt.Printf("[DEBUG evalL0]   hasQuotient = %v (should be 1)\n", hasQuotient)

	p.api.AssertIsEqual(hasQuotient, frontend.Variable(1))

	fmt.Printf("[DEBUG evalL0] ═══════════════════════════════════════════════════════════\n\n")

	return quotient
}

func (p *PlonkChip) checkPartialProducts(
	numerators []gl.QuadraticExtensionVariable,
	denominators []gl.QuadraticExtensionVariable,
	challengeNum uint64,
	openings variables.OpeningSet,
) []gl.QuadraticExtensionVariable {
	glApi := gl.New(p.api)
	numPartProds := p.commonData.NumPartialProducts
	quotDegreeFactor := p.commonData.QuotientDegreeFactor

	productAccs := make([]gl.QuadraticExtensionVariable, 0, numPartProds+2)
	productAccs = append(productAccs, openings.PlonkZs[challengeNum])
	productAccs = append(productAccs, openings.PartialProducts[challengeNum*numPartProds:(challengeNum+1)*numPartProds]...)
	productAccs = append(productAccs, openings.PlonkZsNext[challengeNum])

	partialProductChecks := make([]gl.QuadraticExtensionVariable, 0, numPartProds)

	for i := uint64(0); i <= numPartProds; i += 1 {
		ppStartIdx := i * quotDegreeFactor
		numeProduct := numerators[ppStartIdx]
		denoProduct := denominators[ppStartIdx]
		for j := uint64(1); j < quotDegreeFactor; j++ {
			numeProduct = glApi.MulExtension(numeProduct, numerators[ppStartIdx+j])
			denoProduct = glApi.MulExtension(denoProduct, denominators[ppStartIdx+j])
		}

		partialProductCheck := glApi.SubExtension(
			glApi.MulExtension(productAccs[i], numeProduct),
			glApi.MulExtension(productAccs[i+1], denoProduct),
		)

		partialProductChecks = append(partialProductChecks, partialProductCheck)
	}
	return partialProductChecks
}

func (p *PlonkChip) evalLookupConstraints(
	proofChallenges variables.ProofChallenges,
	openings variables.OpeningSet,
	zetaPowN gl.QuadraticExtensionVariable,
) []gl.QuadraticExtensionVariable {
	// Implement lookup constraint verification for plonky2 v1.1.0+
	// Based on plonky2's check_lookup_constraints in vanishing_poly.rs
	//
	// This involves:
	// 1. RE polynomial constraints (randomized element)
	// 2. Sum polynomial constraints
	// 3. LDC polynomial constraints (logarithmic derivative)
	// 4. SLDC partial product constraints
	//
	// For now, return empty if no lookups (backward compatibility)
	// Full implementation requires access to lookup tables and delta challenges
	if len(openings.LookupZs) == 0 {
		return nil
	}

	// TODO: Implement full lookup verification
	// This is a placeholder that returns empty constraints
	// Full implementation will be added when testing with lookup circuits
	return nil
}

func (p *PlonkChip) evalVanishingPoly(
	vars gates.EvaluationVars,
	proofChallenges variables.ProofChallenges,
	openings variables.OpeningSet,
	zetaPowN gl.QuadraticExtensionVariable,
) []gl.QuadraticExtensionVariable {
	glApi := gl.New(p.api)

	p.debugLog("  3.1: Evaluate Gate Constraints")
	p.debugLog("  ───────────────────────────────")
	constraintTerms := p.evaluateGatesChip.EvaluateGateConstraints(vars)
	p.debugLogf("  Number of constraint terms: %d", len(constraintTerms))

	// Calculate the k[i] * x
	p.debugLog("")
	p.debugLog("  3.2: Calculate s_IDs = k_i * zeta")
	p.debugLog("  ──────────────────────────────────")
	sIDs := make([]gl.QuadraticExtensionVariable, p.commonData.Config.NumRoutedWires)

	for i := uint64(0); i < p.commonData.Config.NumRoutedWires; i++ {
		sIDs[i] = glApi.ScalarMulExtension(proofChallenges.PlonkZeta, p.commonDataKIs[i])
	}
	p.debugLogf("  Computed %d s_IDs", len(sIDs))

	// Calculate L_0(zeta)
	p.debugLog("")
	p.debugLog("  3.3: Calculate L_0(zeta)")
	p.debugLog("  ────────────────────────")
	l0Zeta := p.evalL0(proofChallenges.PlonkZeta, zetaPowN)
	p.debugLogExtension("  L_0(zeta)", l0Zeta)

	p.debugLog("")
	p.debugLog("  3.4: Calculate Z_1 Terms")
	p.debugLog("  ────────────────────────")
	vanishingZ1Terms := make([]gl.QuadraticExtensionVariable, 0, p.commonData.Config.NumChallenges)
	vanishingPartialProductsTerms := make([]gl.QuadraticExtensionVariable, 0, p.commonData.Config.NumChallenges*p.commonData.NumPartialProducts)
	for i := uint64(0); i < p.commonData.Config.NumChallenges; i++ {
		// L_0(zeta) (Z(zeta) - 1) = 0
		z1_term := glApi.MulExtension(
			l0Zeta,
			glApi.SubExtension(openings.PlonkZs[i], gl.OneExtension()),
		)
		vanishingZ1Terms = append(vanishingZ1Terms, z1_term)
		p.debugLogExtensionf("  Z_1_term[%d]", int(i), z1_term)

		numeratorValues := make([]gl.QuadraticExtensionVariable, 0, p.commonData.Config.NumRoutedWires)
		denominatorValues := make([]gl.QuadraticExtensionVariable, 0, p.commonData.Config.NumRoutedWires)
		if i == 0 {
			p.debugLogf("  Challenge 0: Processing %d routed wires", p.commonData.Config.NumRoutedWires)
		}
		for j := uint64(0); j < p.commonData.Config.NumRoutedWires; j++ {
			// The numerator is `beta * s_id + wire_value + gamma`, and the denominator is
			// `beta * s_sigma + wire_value + gamma`.
			wireValuePlusGamma := glApi.AddExtension(
				openings.Wires[j],
				gl.NewQuadraticExtensionVariable(proofChallenges.PlonkGammas[i], gl.Zero()),
			)
			if i == 0 && j < 3 {
				p.debugLogf("    Wire[%d]: [%v, %v]", j, openings.Wires[j][0].Limb, openings.Wires[j][1].Limb)
			}

			numerator := glApi.AddExtension(
				glApi.MulExtension(
					gl.NewQuadraticExtensionVariable(proofChallenges.PlonkBetas[i], gl.Zero()),
					sIDs[j],
				),
				wireValuePlusGamma,
			)

			denominator := glApi.AddExtension(
				glApi.MulExtension(
					gl.NewQuadraticExtensionVariable(proofChallenges.PlonkBetas[i], gl.Zero()),
					openings.PlonkSigmas[j],
				),
				wireValuePlusGamma,
			)

			numeratorValues = append(numeratorValues, numerator)
			denominatorValues = append(denominatorValues, denominator)
		}

		p.debugLog("")
		p.debugLogf("  3.5: Check Partial Products for Challenge %d", i)
		p.debugLog("  ────────────────────────────────────────────")
		partialProductChecks := p.checkPartialProducts(numeratorValues, denominatorValues, i, openings)
		vanishingPartialProductsTerms = append(
			vanishingPartialProductsTerms,
			partialProductChecks...,
		)
		p.debugLogf("  Number of partial product checks: %d", len(partialProductChecks))
		for j, check := range partialProductChecks {
			p.debugLogExtensionf("    Partial product check[%d]", int(j), check)
		}
	}

	// Add lookup constraint terms if lookups are present (v1.1.0+)
	var vanishingLookupTerms []gl.QuadraticExtensionVariable
	if p.commonData.NumLookupPolys > 0 {
		vanishingLookupTerms = p.evalLookupConstraints(
			proofChallenges,
			openings,
			zetaPowN,
		)
	}

	p.debugLog("")
	p.debugLog("  3.6: Combine All Vanishing Terms")
	p.debugLog("  ─────────────────────────────────")

	// First compute partial reduction (Z_1 + partial products) to compare with Rust
	partialTerms := append(vanishingZ1Terms, vanishingPartialProductsTerms...)
	partialReduced := make([]gl.QuadraticExtensionVariable, p.commonData.Config.NumChallenges)
	for i := uint64(0); i < p.commonData.Config.NumChallenges; i++ {
		partialReduced[i] = gl.ZeroExtension()
	}
	for i := len(partialTerms) - 1; i >= 0; i-- {
		for j := uint64(0); j < p.commonData.Config.NumChallenges; j++ {
			partialReduced[j] = glApi.AddExtension(
				partialTerms[i],
				glApi.ScalarMulExtension(
					partialReduced[j],
					proofChallenges.PlonkAlphas[j],
				),
			)
		}
	}
	p.debugLog("  Partial reduction (Z_1 + partial products, NO gate constraints):")
	for i := uint64(0); i < p.commonData.Config.NumChallenges; i++ {
		p.debugLogExtensionf("    partialReduced[%d]", int(i), partialReduced[i])
	}

	// Also compute gate constraint only reduction
	gateOnlyReduced := make([]gl.QuadraticExtensionVariable, p.commonData.Config.NumChallenges)
	for i := uint64(0); i < p.commonData.Config.NumChallenges; i++ {
		gateOnlyReduced[i] = gl.ZeroExtension()
	}
	p.debugLog("  Gate constraints reduction (first/last 3 iterations):")
	for i := len(constraintTerms) - 1; i >= 0; i-- {
		for j := uint64(0); j < p.commonData.Config.NumChallenges; j++ {
			oldVal := gateOnlyReduced[j]
			gateOnlyReduced[j] = glApi.AddExtension(
				constraintTerms[i],
				glApi.ScalarMulExtension(
					gateOnlyReduced[j],
					proofChallenges.PlonkAlphas[j],
				),
			)
			// Log first 3 and last 3 iterations for j=0
			if j == 0 && (i >= len(constraintTerms)-3 || i < 3) {
				p.debugLogf("    [i=%d] term=[%v,%v] old=[%v,%v] new=[%v,%v]",
					i, constraintTerms[i][0].Limb, constraintTerms[i][1].Limb,
					oldVal[0].Limb, oldVal[1].Limb,
					gateOnlyReduced[j][0].Limb, gateOnlyReduced[j][1].Limb)
			}
		}
	}
	p.debugLog("  Gate constraints only reduction:")
	for i := uint64(0); i < p.commonData.Config.NumChallenges; i++ {
		p.debugLogExtensionf("    gateOnlyReduced[%d]", int(i), gateOnlyReduced[i])
	}
	
	vanishingTerms := append(vanishingZ1Terms, vanishingPartialProductsTerms...)
	if len(vanishingLookupTerms) > 0 {
		vanishingTerms = append(vanishingTerms, vanishingLookupTerms...)
	}
	vanishingTerms = append(vanishingTerms, constraintTerms...)

	p.debugLogf("  Z_1 terms: %d", len(vanishingZ1Terms))
	p.debugLogf("  Partial product terms: %d", len(vanishingPartialProductsTerms))
	p.debugLogf("  Lookup terms: %d", len(vanishingLookupTerms))
	p.debugLogf("  Gate constraint terms: %d", len(constraintTerms))
	p.debugLogf("  Total vanishing terms: %d", len(vanishingTerms))

	p.debugLog("")
	p.debugLog("  3.7: Reduce with Powers (alphas)")
	p.debugLog("  ─────────────────────────────────")
	p.debugLogf("  Alpha[0]: [%v]", proofChallenges.PlonkAlphas[0].Limb)
	p.debugLogf("  Alpha[1]: [%v]", proofChallenges.PlonkAlphas[1].Limb)

	reducedValues := make([]gl.QuadraticExtensionVariable, p.commonData.Config.NumChallenges)
	for i := uint64(0); i < p.commonData.Config.NumChallenges; i++ {
		reducedValues[i] = gl.ZeroExtension()
	}

	// Show first few and last few terms
	p.debugLog("")
	p.debugLogf("  First 3 vanishing terms (from end, will be processed first):")
	for i := len(vanishingTerms) - 1; i >= len(vanishingTerms)-3 && i >= 0; i-- {
		p.debugLogExtensionf("    term[%d]", i, vanishingTerms[i])
	}

	// reverse iterate the vanishingPartialProductsTerms array
	for i := len(vanishingTerms) - 1; i >= 0; i-- {
		for j := uint64(0); j < p.commonData.Config.NumChallenges; j++ {
			oldValue := reducedValues[j]
			reducedValues[j] = glApi.AddExtension(
				vanishingTerms[i],
				glApi.ScalarMulExtension(
					reducedValues[j],
					proofChallenges.PlonkAlphas[j],
				),
			)
			// Log first few iterations for debugging
			if i >= len(vanishingTerms)-3 {
				p.debugLogf("    Iter i=%d, j=%d:", i, j)
				p.debugLogExtensionf("      old reducedValue[%d]", int(j), oldValue)
				p.debugLogExtensionf("      new reducedValue[%d]", int(j), reducedValues[j])
			}
		}
	}

	p.debugLog("")
	p.debugLog("  Reduced values computed:")
	for i := uint64(0); i < p.commonData.Config.NumChallenges; i++ {
		p.debugLogExtensionf("  reducedValue[%d]", int(i), reducedValues[i])
	}

	return reducedValues
}

func (p *PlonkChip) Verify(
	proofChallenges variables.ProofChallenges,
	openings variables.OpeningSet,
	publicInputsHash poseidon.GoldilocksHashOut,
) {
	glApi := gl.New(p.api)

	// DEBUG: Print key input values
	p.debugLog("╔════════════════════════════════════════════════════════════════╗")
	p.debugLog("║  GNARK PLONK VERIFIER DEBUG TRACE                             ║")
	p.debugLog("╚════════════════════════════════════════════════════════════════╝")
	p.debugLog("")
	p.debugLog("STEP 1: Proof Openings")
	p.debugLog("══════════════════════════════════════════════════════════════")
	p.debugLog("")
	p.debugLogf("Proof Openings:")
	p.debugLogf("  Constants (%d elements):", len(openings.Constants))
	for i, c := range openings.Constants {
		p.debugLogExtensionf("    [%d]", i, c)
	}
	p.debugLog("")
	p.debugLogf("  Wires (%d elements):", len(openings.Wires))
	for i, w := range openings.Wires {
		p.debugLogExtensionf("    [%d]", i, w)
	}
	p.debugLog("")
	p.debugLogf("  PlonkZs (%d elements):", len(openings.PlonkZs))
	for i, z := range openings.PlonkZs {
		p.debugLogExtensionf("    [%d]", i, z)
	}
	p.debugLog("")
	p.debugLogf("  PlonkZsNext (%d elements):", len(openings.PlonkZsNext))
	for i, zn := range openings.PlonkZsNext {
		p.debugLogExtensionf("    [%d]", i, zn)
	}
	p.debugLog("")
	p.debugLogf("  PartialProducts (%d elements):", len(openings.PartialProducts))
	for i, pp := range openings.PartialProducts {
		p.debugLogExtensionf("    [%d]", i, pp)
	}
	p.debugLog("")
	p.debugLogf("  QuotientPolys (%d elements):", len(openings.QuotientPolys))
	for i, qp := range openings.QuotientPolys {
		p.debugLogExtensionf("    [%d]", i, qp)
	}
	p.debugLog("")
	p.debugLog("✅ Plonk openings traced")
	p.debugLog("")
	p.debugLog("STEP 2: Input Values")
	p.debugLog("────────────────────")
	p.debugLogExtension("zeta", proofChallenges.PlonkZeta)

	// Calculate zeta^n
	p.debugLog("")
	p.debugLog("STEP 3: Compute zeta^n")
	p.debugLog("──────────────────────")
	zetaPowN := p.expPowerOf2Extension(proofChallenges.PlonkZeta)
	p.debugLogExtension("zeta^n", zetaPowN)

	localConstants := openings.Constants
	localWires := openings.Wires
	vars := gates.NewEvaluationVars(
		localConstants,
		localWires,
		publicInputsHash,
	)

	p.debugLog("")
	p.debugLog("STEP 4: Evaluate Vanishing Polynomial")
	p.debugLog("──────────────────────────────────────")
	vanishingPolysZeta := p.evalVanishingPoly(*vars, proofChallenges, openings, zetaPowN)

	// Calculate Z(H)
	p.debugLog("")
	p.debugLog("STEP 5: Compute Z_H(zeta)")
	p.debugLog("─────────────────────────")
	zHZeta := glApi.SubExtension(zetaPowN, gl.OneExtension())
	p.debugLogExtension("Z_H(zeta)", zHZeta)

	// `quotient_polys_zeta` holds `num_challenges * quotient_degree_factor` evaluations.
	// Each chunk of `quotient_degree_factor` holds the evaluations of `t_0(zeta),...,t_{quotient_degree_factor-1}(zeta)`
	// where the "real" quotient polynomial is `t(X) = t_0(X) + t_1(X)*X^n + t_2(X)*X^{2n} + ...`.
	// So to reconstruct `t(zeta)` we can compute `reduce_with_powers(chunk, zeta^n)` for each
	// `quotient_degree_factor`-sized chunk of the original evaluations.
	p.debugLog("")
	p.debugLog("STEP 6: Reconstruct Quotient Polynomials and Verify")
	p.debugLog("────────────────────────────────────────────────────")
	p.debugLogf("Number of quotient polys: %d", len(openings.QuotientPolys))
	p.debugLogf("QuotientDegreeFactor: %d", p.commonData.QuotientDegreeFactor)
	p.debugLogExtension("zetaPowN", zetaPowN)

	for i := 0; i < len(vanishingPolysZeta); i++ {
		p.debugLogf("Challenge %d:", i)

		quotientPolysStartIdx := i * int(p.commonData.QuotientDegreeFactor)
		quotientPolysEndIdx := quotientPolysStartIdx + int(p.commonData.QuotientDegreeFactor)

		p.debugLogf("  quotient polys range: [%d:%d]", quotientPolysStartIdx, quotientPolysEndIdx)
		for j := quotientPolysStartIdx; j < quotientPolysEndIdx && j < len(openings.QuotientPolys); j++ {
			p.debugLogExtension(fmt.Sprintf("    quotientPoly[%d]", j), openings.QuotientPolys[j])
		}

		tZeta := glApi.ReduceWithPowers(
			openings.QuotientPolys[quotientPolysStartIdx:quotientPolysEndIdx],
			zetaPowN,
		)
		p.debugLogExtension("  t(zeta)", tZeta)

		prod := glApi.MulExtension(zHZeta, tZeta)
		p.debugLogExtension("  Z_H(zeta) * t(zeta)", prod)
		p.debugLogExtension("  vanishingPolyZeta[i]", vanishingPolysZeta[i])

		glApi.AssertIsEqualExtension(vanishingPolysZeta[i], prod)
	}

	p.debugLog("")
	p.debugLog("╔════════════════════════════════════════════════════════════════╗")
	p.debugLog("║  END GNARK PLONK VERIFIER DEBUG TRACE                         ║")
	p.debugLog("╚════════════════════════════════════════════════════════════════╝")
}

// Debug logging helpers
func (p *PlonkChip) debugLog(msg string) {
	fmt.Println(msg)
}

func (p *PlonkChip) debugLogf(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

func (p *PlonkChip) debugLogExtension(name string, val gl.QuadraticExtensionVariable) {
	fmt.Printf("%s: [%v, %v]\n", name, val[0].Limb, val[1].Limb)
}

func (p *PlonkChip) debugLogExtensionf(format string, idx int, val gl.QuadraticExtensionVariable) {
	fmt.Printf(format+": [%v, %v]\n", idx, val[0].Limb, val[1].Limb)
}
