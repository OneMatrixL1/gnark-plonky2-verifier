package gates

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
)

type EvaluateGatesChip struct {
	api frontend.API

	gates              []Gate
	numGateConstraints uint64
	numLookupSelectors uint64

	selectorsInfo SelectorsInfo
}

func NewEvaluateGatesChip(
	api frontend.API,
	gates []Gate,
	numGateConstraints uint64,
	numLookupSelectors uint64,
	selectorsInfo SelectorsInfo,
) *EvaluateGatesChip {
	return &EvaluateGatesChip{
		api: api,

		gates:              gates,
		numGateConstraints: numGateConstraints,
		numLookupSelectors: numLookupSelectors,

		selectorsInfo: selectorsInfo,
	}
}

func (g *EvaluateGatesChip) computeFilter(
	row uint64,
	groupRange Range,
	s gl.QuadraticExtensionVariable,
	manySelector bool,
) gl.QuadraticExtensionVariable {
	glApi := gl.New(g.api)
	product := gl.OneExtension()

	fmt.Printf("    [FILTER] row=%d, group=[%d,%d), s=[%v,%v], manySelector=%v\n",
		row, groupRange.start, groupRange.end, s[0].Limb, s[1].Limb, manySelector)

	for i := groupRange.start; i < groupRange.end; i++ {
		if i == uint64(row) {
			continue
		}
		tmp := gl.NewQuadraticExtensionVariable(gl.NewVariable(i), gl.Zero())
		factor := glApi.SubExtension(tmp, s)
		fmt.Printf("    [FILTER]   factor[%d] = %d - s = [%v,%v]\n",
			i, i, factor[0].Limb, factor[1].Limb)
		product = glApi.MulExtension(product, factor)
	}

	if manySelector {
		tmp := gl.NewQuadraticExtensionVariable(gl.NewVariable(UNUSED_SELECTOR), gl.Zero())
		factor := glApi.SubExtension(tmp, s)
		fmt.Printf("    [FILTER]   factor[UNUSED=%d] = %d - s = [%v,%v]\n",
			UNUSED_SELECTOR, UNUSED_SELECTOR, factor[0].Limb, factor[1].Limb)
		product = glApi.MulExtension(product, factor)
	}

	fmt.Printf("    [FILTER]   final product = [%v,%v]\n", product[0].Limb, product[1].Limb)
	return product
}

func (g *EvaluateGatesChip) evalFiltered(
	gate Gate,
	vars EvaluationVars,
	row uint64,
	selectorIndex uint64,
	groupRange Range,
	numSelectors uint64,
	numLookupSelectors uint64,
) []gl.QuadraticExtensionVariable {
	glApi := gl.New(g.api)
	filter := g.computeFilter(row, groupRange, vars.localConstants[selectorIndex], numSelectors > 1)

	vars.RemovePrefix(numSelectors)
	vars.RemovePrefix(numLookupSelectors)

	// Log first few local constants and wires for Gates 0-2 to compare with Rust
	if row <= 2 {
		fmt.Printf("  [GATE_EVAL] Gate %d inputs:\n", row)
		numToLog := 5
		if len(vars.localConstants) < numToLog {
			numToLog = len(vars.localConstants)
		}
		for i := 0; i < numToLog; i++ {
			fmt.Printf("    localConstants[%d] = [%v, %v]\n",
				i, vars.localConstants[i][0].Limb, vars.localConstants[i][1].Limb)
		}
		if len(vars.localWires) < numToLog {
			numToLog = len(vars.localWires)
		}
		for i := 0; i < numToLog; i++ {
			fmt.Printf("    localWires[%d] = [%v, %v]\n",
				i, vars.localWires[i][0].Limb, vars.localWires[i][1].Limb)
		}
		// For PublicInputGate, also log the public inputs hash
		if row == 1 {
			fmt.Printf("    publicInputsHash:\n")
			for i := 0; i < len(vars.publicInputsHash); i++ {
				fmt.Printf("      [%d] = %v\n", i, vars.publicInputsHash[i].Limb)
			}
		}
	}

	unfiltered := gate.EvalUnfiltered(g.api, glApi, vars)

	// Log first few UNFILTERED constraints for debugging
	fmt.Printf("  [GATE_EVAL] Gate row=%d, %d unfiltered constraints\n", row, len(unfiltered))
	numToLog := 3
	if len(unfiltered) < numToLog {
		numToLog = len(unfiltered)
	}
	for i := 0; i < numToLog; i++ {
		fmt.Printf("  [GATE_EVAL]   unfiltered[%d] = [%v, %v]\n",
			i, unfiltered[i][0].Limb, unfiltered[i][1].Limb)
	}

	for i := range unfiltered {
		unfiltered[i] = glApi.MulExtension(unfiltered[i], filter)
	}

	// Log first few FILTERED constraints for debugging
	fmt.Printf("  [GATE_EVAL] After filtering (filter=[%v,%v]):\n", filter[0].Limb, filter[1].Limb)
	for i := 0; i < numToLog; i++ {
		fmt.Printf("  [GATE_EVAL]   filtered[%d] = [%v, %v]\n",
			i, unfiltered[i][0].Limb, unfiltered[i][1].Limb)
	}

	return unfiltered
}

func (g *EvaluateGatesChip) EvaluateGateConstraints(vars EvaluationVars) []gl.QuadraticExtensionVariable {
	glApi := gl.New(g.api)
	constraints := make([]gl.QuadraticExtensionVariable, g.numGateConstraints)
	for i := range constraints {
		constraints[i] = gl.ZeroExtension()
	}

	fmt.Printf("  [DEBUG] Evaluating %d gates, total constraints: %d\n", len(g.gates), g.numGateConstraints)

	for i, gate := range g.gates {
		selectorIndex := g.selectorsInfo.selectorIndices[i]

		fmt.Printf("  [DEBUG] Gate %d: type=%T, selectorIndex=%d\n", i, gate, selectorIndex)

		gateConstraints := g.evalFiltered(
			gate,
			vars,
			uint64(i),
			selectorIndex,
			g.selectorsInfo.groups[selectorIndex],
			g.selectorsInfo.NumSelectors(),
			g.numLookupSelectors,
		)

		fmt.Printf("  [DEBUG]   Generated %d constraints\n", len(gateConstraints))
		if len(gateConstraints) > 0 && len(gateConstraints) <= 3 {
			for j, c := range gateConstraints {
				fmt.Printf("  [DEBUG]     constraint[%d]: [%v, %v]\n", j, c[0].Limb, c[1].Limb)
			}
		}

		fmt.Printf("  [DEBUG]   Accumulating constraints into indices 0-%d (before loop)\n", len(gateConstraints)-1)
		for j, constraint := range gateConstraints {
			if uint64(j) >= g.numGateConstraints {
				fmt.Printf("  [DEBUG]   ERROR: j=%d >= numGateConstraints=%d\n", j, g.numGateConstraints)
				panic("num_constraints() gave too low of a number")
			}
			oldVal := constraints[j]
			constraints[j] = glApi.AddExtension(constraints[j], constraint)
			if j < 1 {  // Debug constraint[0] for all gates
				fmt.Printf("  [DEBUG]     [gate=%d, constraint=%d] old=[%v,%v] + new=[%v,%v] = result=[%v,%v]\n",
					i, j,
					oldVal[0].Limb, oldVal[1].Limb,
					constraint[0].Limb, constraint[1].Limb,
					constraints[j][0].Limb, constraints[j][1].Limb)
			}
		}
	}

	fmt.Printf("  [DEBUG] Final gate constraints (ALL %d):\n", len(constraints))
	for i := 0; i < len(constraints); i++ {
		fmt.Printf("  [DEBUG]   gateConstraint[%d]: [%v, %v]\n", i, constraints[i][0].Limb, constraints[i][1].Limb)
	}

	return constraints
}
