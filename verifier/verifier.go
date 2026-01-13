package verifier

import (
	"fmt"
	"log"
	"os"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/challenger"
	"github.com/succinctlabs/gnark-plonky2-verifier/fri"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/plonk"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
)

type VerifierChip struct {
	api               frontend.API             `gnark:"-"`
	glChip            *gl.Chip                 `gnark:"-"`
	poseidonGlChip    *poseidon.GoldilocksChip `gnark:"-"`
	poseidonBN254Chip *poseidon.BN254Chip      `gnark:"-"`
	plonkChip         *plonk.PlonkChip         `gnark:"-"`
	friChip           *fri.Chip                `gnark:"-"`
	commonData        types.CommonCircuitData  `gnark:"-"`
	hashMode          types.HashMode           `gnark:"-"`
}

var debugBN254Trace = os.Getenv("DEBUG_BN254_TRACE") == "1"

func debugBN254Println(args ...interface{}) {
	if debugBN254Trace {
		fmt.Println(args...)
	}
}

func DebugPrintHash(label string, hash poseidon.GoldilocksHashOut, mode types.HashMode) {
	if !debugBN254Trace {
		return
	}
	fmt.Printf("%s (%v mode): [%v, %v, %v, %v]\n", label, mode, hash[0].Limb, hash[1].Limb, hash[2].Limb, hash[3].Limb)
}

func DebugPrintCap(label string, cap []poseidon.GoldilocksHashOut, mode types.HashMode) {
	if !debugBN254Trace {
		return
	}
	fmt.Printf("%s (size %d):\n", label, len(cap))
	for i, hash := range cap {
		DebugPrintHash(fmt.Sprintf("  [%d]", i), hash, mode)
	}
}

func DebugPrintChallenges(label string, ch []gl.Variable) {
	if !debugBN254Trace {
		return
	}
	fmt.Printf("%s (%d):\n", label, len(ch))
	for i, v := range ch {
		fmt.Printf("  [%d] = %v\n", i, v.Limb)
	}
}

func DebugPrintExtensionChallenge(label string, ch gl.QuadraticExtensionVariable) {
	if !debugBN254Trace {
		return
	}
	fmt.Printf("%s = [%v, %v]\n", label, ch[0].Limb, ch[1].Limb)
}

func NewVerifierChip(api frontend.API, commonCircuitData types.CommonCircuitData, hashMode types.HashMode) *VerifierChip {
	glChip := gl.New(api)
	friChip := fri.NewChip(api, &commonCircuitData, &commonCircuitData.FriParams, hashMode)
	plonkChip := plonk.NewPlonkChip(api, commonCircuitData)
	poseidonGlChip := poseidon.NewGoldilocksChip(api)
	poseidonBN254Chip := poseidon.NewBN254Chip(api)
	return &VerifierChip{
		api:               api,
		glChip:            glChip,
		poseidonGlChip:    poseidonGlChip,
		poseidonBN254Chip: poseidonBN254Chip,
		plonkChip:         plonkChip,
		friChip:           friChip,
		commonData:        commonCircuitData,
		hashMode:          hashMode,
	}
}

func (c *VerifierChip) GetPublicInputsHash(publicInputs []gl.Variable) poseidon.GoldilocksHashOut {
	// CRITICAL: In Plonky2's PoseidonBN128GoldilocksConfig, public_inputs_hash
	// is computed using InnerHasher (Goldilocks Poseidon), NOT the outer Hasher (BN254 Poseidon).
	// This is because public inputs are Goldilocks field elements and are hashed
	// internally before being observed by the challenger.
	// See plonky2_bn128_config.rs: type InnerHasher = PoseidonHash;
	return c.poseidonGlChip.HashNoPad(publicInputs)
}

func (c *VerifierChip) GetChallenges(
	proof variables.Proof,
	publicInputsHash poseidon.GoldilocksHashOut,
	verifierData variables.VerifierOnlyCircuitData,
) variables.ProofChallenges {
	if debugBN254Trace {
		debugBN254Println("╔════════════════════════════════════════════════════════════════╗")
		debugBN254Println("║  GNARK BN254 VERIFIER TRACE - CHALLENGE GENERATION            ║")
		debugBN254Println("╚════════════════════════════════════════════════════════════════╝")
		debugBN254Println()
	}

	config := c.commonData.Config
	numChallenges := config.NumChallenges
	challengerChip := challenger.NewChip(c.api, c.hashMode)

	// CRITICAL: Observe FRI params FIRST, before circuit_digest
	// This matches Rust's get_challenges: common_data.fri_params.observe(&mut challenger)
	if debugBN254Trace {
		debugBN254Println("STEP 1: Observe FRI Params")
		debugBN254Println("══════════════════════════")
	}
	challengerChip.ObserveFriParams(c.commonData.FriParams, c.commonData.FriParams.Config, c.commonData.ReductionStrategy)

	var circuitDigest = verifierData.CircuitDigest

	if debugBN254Trace {
		debugBN254Println("\nSTEP 2: Observe Circuit Digest and Public Inputs Hash")
		debugBN254Println("══════════════════════════════════════════════════════")
		DebugPrintHash("Circuit digest", circuitDigest, c.hashMode)
		DebugPrintHash("Public inputs hash", publicInputsHash, c.hashMode)
	}

	// In BN254 mode, circuit_digest is a BN254 hash (stored as 4 u64 chunks, observed as 5 elements)
	// But public_inputs_hash is ALWAYS a Goldilocks hash (4 elements) - uses InnerHasher in Rust
	if c.hashMode == types.HashModePoseidonBN254 {
		log.Printf("[VERIFIER] BN254 MODE DETECTED - calling ObserveHashFromChunks for circuit_digest")
		if debugBN254Trace {
			debugBN254Println("  → Using BN254 mode: ObserveHashFromChunks for circuit_digest")
		}
		challengerChip.ObserveHashFromChunks(circuitDigest)
		if debugBN254Trace {
			debugBN254Println("  → Using Goldilocks mode: ObserveHash for public_inputs_hash")
		}
		challengerChip.ObserveHash(publicInputsHash) // Goldilocks hash, NOT BN254!

		if debugBN254Trace {
			debugBN254Println("\nSTEP 3: Observe Wires Cap")
			debugBN254Println("═════════════════════════")
			DebugPrintCap("Wires cap", proof.WiresCap, c.hashMode)
		}
		challengerChip.ObserveCapBN254(proof.WiresCap)
	} else {
		challengerChip.ObserveHash(circuitDigest)
		challengerChip.ObserveHash(publicInputsHash)
		challengerChip.ObserveCap(proof.WiresCap)
	}

	if debugBN254Trace {
		debugBN254Println("\nSTEP 4: Extract plonk_betas and plonk_gammas")
		debugBN254Println("═════════════════════════════════════════════")
	}
	plonkBetas := challengerChip.GetNChallenges(numChallenges)
	plonkGammas := challengerChip.GetNChallenges(numChallenges)

	if debugBN254Trace {
		DebugPrintChallenges("plonk_betas", plonkBetas)
		DebugPrintChallenges("plonk_gammas", plonkGammas)
	}

	// Generate lookup challenges if lookups are present (v1.1.0+)
	var plonkDeltas []gl.Variable
	if c.commonData.NumLookupPolys > 0 {
		// In plonky2 v1.1.0, lookup challenges use NUM_COINS_LOOKUP = 4
		// deltas = [betas, gammas, 2 more challenges per copy]
		// Total = 4 * numChallenges, but first 2*numChallenges are reused
		numLookupChallenges := 4 * numChallenges
		plonkDeltas = make([]gl.Variable, numLookupChallenges)
		copy(plonkDeltas[:numChallenges], plonkBetas)
		copy(plonkDeltas[numChallenges:2*numChallenges], plonkGammas)
		// Get remaining 2 * numChallenges challenges
		remaining := challengerChip.GetNChallenges(2 * numChallenges)
		copy(plonkDeltas[2*numChallenges:], remaining)
	}

	if debugBN254Trace {
		debugBN254Println("\nSTEP 5: Observe PlonkZsPartialProducts Cap")
		debugBN254Println("═══════════════════════════════════════════")
		DebugPrintCap("PlonkZsPartialProducts cap", proof.PlonkZsPartialProductsCap, c.hashMode)
	}

	if c.hashMode == types.HashModePoseidonBN254 {
		challengerChip.ObserveCapBN254(proof.PlonkZsPartialProductsCap)
	} else {
		challengerChip.ObserveCap(proof.PlonkZsPartialProductsCap)
	}

	if debugBN254Trace {
		debugBN254Println("\nSTEP 6: Extract plonk_alphas")
		debugBN254Println("════════════════════════════")
	}
	plonkAlphas := challengerChip.GetNChallenges(numChallenges)

	if debugBN254Trace {
		DebugPrintChallenges("plonk_alphas", plonkAlphas)
		debugBN254Println("\nSTEP 7: Observe Quotient Polys Cap")
		debugBN254Println("═══════════════════════════════════")
		DebugPrintCap("Quotient polys cap", proof.QuotientPolysCap, c.hashMode)
	}

	if c.hashMode == types.HashModePoseidonBN254 {
		challengerChip.ObserveCapBN254(proof.QuotientPolysCap)
	} else {
		challengerChip.ObserveCap(proof.QuotientPolysCap)
	}

	if debugBN254Trace {
		debugBN254Println("\nSTEP 8: Extract plonk_zeta")
		debugBN254Println("═══════════════════════════")
	}
	plonkZeta := challengerChip.GetExtensionChallenge()

	if debugBN254Trace {
		DebugPrintExtensionChallenge("plonk_zeta", plonkZeta)
		debugBN254Println()
		debugBN254Println("✅ Challenge generation complete")
		debugBN254Println("════════════════════════════════════════════════════════════════")
		debugBN254Println()
	}

	challengerChip.ObserveOpenings(c.friChip.ToOpenings(proof.Openings))

	return variables.ProofChallenges{
		PlonkBetas:  plonkBetas,
		PlonkGammas: plonkGammas,
		PlonkAlphas: plonkAlphas,
		PlonkDeltas: plonkDeltas,
		PlonkZeta:   plonkZeta,
		FriChallenges: challengerChip.GetFriChallenges(
			proof.OpeningProof.CommitPhaseMerkleCaps,
			proof.OpeningProof.FinalPoly,
			proof.OpeningProof.PowWitness,
			config.FriConfig,
			c.commonData.DegreeBits,
		),
	}
}

func (c *VerifierChip) rangeCheckProof(proof variables.Proof) {
	// In BN254 mode, the proof values are not Goldilocks field elements
	// They are BN254 field elements split into 4 u64 chunks for wire compatibility
	// So we skip Goldilocks range checks in BN254 mode
	if c.hashMode == types.HashModePoseidonBN254 {
		// In BN254 mode, values are native BN254 field elements in the circuit
		// No Goldilocks range checking needed
		return
	}

	// Need to verify the plonky2 proof's openings, openings proof (other than the sibling elements), fri's final poly, pow witness.

	// Note that this is NOT range checking the public inputs (first 32 elements should be no more than 8 bits and the last 4 elements should be no more than 64 bits).  Since this is currently being inputted via the smart contract,
	// we will assume that caller is doing that check.

	// Range check the proof's openings.
	for _, constant := range proof.Openings.Constants {
		c.glChip.RangeCheckQE(constant)
	}

	for _, plonkSigma := range proof.Openings.PlonkSigmas {
		c.glChip.RangeCheckQE(plonkSigma)
	}

	for _, wire := range proof.Openings.Wires {
		c.glChip.RangeCheckQE(wire)
	}

	for _, plonkZ := range proof.Openings.PlonkZs {
		c.glChip.RangeCheckQE(plonkZ)
	}

	for _, plonkZNext := range proof.Openings.PlonkZsNext {
		c.glChip.RangeCheckQE(plonkZNext)
	}

	for _, partialProduct := range proof.Openings.PartialProducts {
		c.glChip.RangeCheckQE(partialProduct)
	}

	for _, quotientPoly := range proof.Openings.QuotientPolys {
		c.glChip.RangeCheckQE(quotientPoly)
	}

	for _, lookupZ := range proof.Openings.LookupZs {
		c.glChip.RangeCheckQE(lookupZ)
	}

	for _, lookupZNext := range proof.Openings.LookupZsNext {
		c.glChip.RangeCheckQE(lookupZNext)
	}

	// Range check the openings proof.
	for _, queryRound := range proof.OpeningProof.QueryRoundProofs {
		for _, evalsProof := range queryRound.InitialTreesProof.EvalsProofs {
			for _, evalsProofElement := range evalsProof.Elements {
				c.glChip.RangeCheck(evalsProofElement)
			}
		}

		for _, queryStep := range queryRound.Steps {
			for _, eval := range queryStep.Evals {
				c.glChip.RangeCheckQE(eval)
			}
		}
	}

	// Range check the fri's final poly.
	for _, coeff := range proof.OpeningProof.FinalPoly.Coeffs {
		c.glChip.RangeCheckQE(coeff)
	}

	// Range check the pow witness.
	c.glChip.RangeCheck(proof.OpeningProof.PowWitness)
}

func (c *VerifierChip) Verify(
	proof variables.Proof,
	publicInputs []gl.Variable,
	verifierData variables.VerifierOnlyCircuitData,
) {
	c.rangeCheckProof(proof)

	// Generate the parts of the witness that is for the plonky2 proof input
	publicInputsHash := c.GetPublicInputsHash(publicInputs)
	proofChallenges := c.GetChallenges(proof, publicInputsHash, verifierData)

	c.plonkChip.Verify(proofChallenges, proof.Openings, publicInputsHash)

	initialMerkleCaps := []variables.FriMerkleCap{
		verifierData.ConstantSigmasCap,
		proof.WiresCap,
		proof.PlonkZsPartialProductsCap,
		proof.QuotientPolysCap,
	}

	c.friChip.VerifyFriProof(
		c.friChip.GetInstance(proofChallenges.PlonkZeta),
		c.friChip.ToOpenings(proof.Openings),
		&proofChallenges.FriChallenges,
		initialMerkleCaps,
		&proof.OpeningProof,
	)
}
