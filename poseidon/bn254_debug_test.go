package poseidon_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
)

type DebugBN254PoseidonCircuit struct {
	Input        [3]gl.Variable
	ExpectedHash [4]frontend.Variable
}

func (c *DebugBN254PoseidonCircuit) Define(api frontend.API) error {
	chip := poseidon.NewBN254Chip(api)
	input := make([]gl.Variable, len(c.Input))
	copy(input, c.Input[:])
	hash := chip.HashOrNoop(input)
	assertHashChunks(api, hash, c.ExpectedHash)
	return nil
}

type DebugBN254HashNoPadCircuit struct {
	Input        [6]gl.Variable
	ExpectedHash [4]frontend.Variable
}

func (c *DebugBN254HashNoPadCircuit) Define(api frontend.API) error {
	chip := poseidon.NewBN254Chip(api)
	input := make([]gl.Variable, len(c.Input))
	copy(input, c.Input[:])
	hash := chip.HashNoPad(input)
	assertHashChunks(api, hash, c.ExpectedHash)
	return nil
}

type DebugBN254TwoToOneCircuit struct {
	LeftChunks     [4]frontend.Variable
	RightChunks    [4]frontend.Variable
	ExpectedChunks [4]frontend.Variable
}

func (c *DebugBN254TwoToOneCircuit) Define(api frontend.API) error {
	chip := poseidon.NewBN254Chip(api)
	left := chunksToHash(api, c.LeftChunks)
	right := chunksToHash(api, c.RightChunks)
	result := chip.TwoToOne(left, right)
	assertHashChunks(api, result, c.ExpectedChunks)
	return nil
}

type DebugBN254HashOrNoop84Circuit struct {
	Input        [84]gl.Variable
	ExpectedHash [4]frontend.Variable
}

func (c *DebugBN254HashOrNoop84Circuit) Define(api frontend.API) error {
	chip := poseidon.NewBN254Chip(api)
	input := make([]gl.Variable, len(c.Input))
	copy(input, c.Input[:])
	hash := chip.HashOrNoop(input)
	assertHashChunks(api, hash, c.ExpectedHash)
	return nil
}

func chunksToHash(api frontend.API, chunks [4]frontend.Variable) poseidon.BN254HashOut {
	var allBits []frontend.Variable
	for i := 0; i < 4; i++ {
		bits := api.ToBinary(chunks[i], 64)
		allBits = append(allBits, bits...)
	}
	return api.FromBinary(allBits...)
}

func assertHashChunks(api frontend.API, hash poseidon.BN254HashOut, expected [4]frontend.Variable) {
	bits := api.ToBinary(hash, 256)
	for i := 0; i < 4; i++ {
		start := i * 64
		chunk := api.FromBinary(bits[start : start+64]...)
		api.AssertIsEqual(chunk, expected[i])
	}
}

func TestBN254HashOrNoopDebug(t *testing.T) {
	assert := test.NewAssert(t)

	hash0, _ := new(big.Int).SetString("15466011800656722675", 10)
	hash1, _ := new(big.Int).SetString("12008768497160901216", 10)
	hash2, _ := new(big.Int).SetString("11537767401799544433", 10)
	hash3, _ := new(big.Int).SetString("1987997952413805088", 10)

	circuit := DebugBN254PoseidonCircuit{}
	witness := DebugBN254PoseidonCircuit{
		Input: [3]gl.Variable{
			gl.NewVariable(1),
			gl.NewVariable(2),
			gl.NewVariable(3),
		},
		ExpectedHash: [4]frontend.Variable{
			frontend.Variable(hash0),
			frontend.Variable(hash1),
			frontend.Variable(hash2),
			frontend.Variable(hash3),
		},
	}

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestBN254HashNoPadDebug(t *testing.T) {
	assert := test.NewAssert(t)

	hash0, _ := new(big.Int).SetString("2599210564925437558", 10)
	hash1, _ := new(big.Int).SetString("3914490162138698338", 10)
	hash2, _ := new(big.Int).SetString("3564140359192216555", 10)
	hash3, _ := new(big.Int).SetString("2446886171559309635", 10)

	circuit := DebugBN254HashNoPadCircuit{}
	witness := DebugBN254HashNoPadCircuit{
		Input: [6]gl.Variable{
			gl.NewVariable(1),
			gl.NewVariable(2),
			gl.NewVariable(3),
			gl.NewVariable(4),
			gl.NewVariable(5),
			gl.NewVariable(6),
		},
		ExpectedHash: [4]frontend.Variable{
			frontend.Variable(hash0),
			frontend.Variable(hash1),
			frontend.Variable(hash2),
			frontend.Variable(hash3),
		},
	}

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestBN254TwoToOneDebug(t *testing.T) {
	assert := test.NewAssert(t)

	left := [...]string{
		"15466011800656722675", "12008768497160901216", "11537767401799544433", "1987997952413805088",
	}
	right := [...]string{
		"10873462239773348242", "347447793939967780", "13491535940621729299", "487912301598569368",
	}
	result := [...]string{
		"16128512216478643329", "3783309186031076904", "7309650014280787840", "3219218551541639315",
	}

	var leftChunks, rightChunks, expected [4]frontend.Variable
	for i := 0; i < 4; i++ {
		l, _ := new(big.Int).SetString(left[i], 10)
		r, _ := new(big.Int).SetString(right[i], 10)
		res, _ := new(big.Int).SetString(result[i], 10)
		leftChunks[i] = frontend.Variable(l)
		rightChunks[i] = frontend.Variable(r)
		expected[i] = frontend.Variable(res)
	}

	circuit := DebugBN254TwoToOneCircuit{}
	witness := DebugBN254TwoToOneCircuit{
		LeftChunks:     leftChunks,
		RightChunks:    rightChunks,
		ExpectedChunks: expected,
	}

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestBN254HashOrNoop84Debug(t *testing.T) {
	assert := test.NewAssert(t)

	sample := []uint64{
		3181647474470254317, 2763264791309470123, 5088546340718160389, 8619233912499420110,
		10782342125713967813, 6330916588133174829, 17657503210266322423, 5999710708824949629,
		4291274822980333559, 2803483319195519299, 16126651736629072029, 5348064131778853785,
		4419573968182820764, 14774029871383768800, 1169604539331248360, 8123670870735593516,
		10631952793433219251, 15939528000130614575, 3971580394746090070, 14573343193074557115,
		10652959590475472393, 7849091091036232185, 17195143574435697446, 7594742666066144589,
		11375974006038021428, 12950863734641938927, 4283337457838954493, 10648330259967391909,
		10020567369748815388, 13501666111702631187, 14599112424720647277, 5321547894582623846,
		2833735599811008796, 11813200132311942513, 826367795103521313, 1251237378809946416,
		7976994294636199046, 16711829819274603849, 11618142371244338696, 18173447602344900399,
		5697461071632161868, 6837520646292036019, 11641296706663416589, 554463323806700091,
		15024824824756591465, 1408431301093773536, 16465528046932257280, 11167743898260391009,
		13659309364080532814, 14848173378269367422, 4284500381118332467, 18133925144808317834,
		10394055281269103008, 11047238633248846068, 2215657689406195936, 2060612267070842249,
		10957128281649999123, 11871711308455794543, 3349049596233166884, 10668673355866573126,
		927460418432792093, 3617730884726688388, 2473425069400336332, 11388819084881583379,
		8949617971104014409, 8541773434048843158, 11118187039173978520, 4116117771978252977,
		9105506874671079948, 11734685876863937897, 17667629060140600733, 11934777220410192768,
		8740365497433338178, 14883028665805963416, 6146138202232493106, 16102898571151392980,
		5034145977035689893, 9278355346466046721, 15795957441928355772, 12499556902689099838,
		6787243473439627210, 10202108228566702296, 10807890785304835721, 5871898312297587475,
	}

	hash0, _ := new(big.Int).SetString("15500771281194193234", 10)
	hash1, _ := new(big.Int).SetString("16499566360280570203", 10)
	hash2, _ := new(big.Int).SetString("13859028303954833084", 10)
	hash3, _ := new(big.Int).SetString("489606248981849403", 10)

	var input [84]gl.Variable
	for i := 0; i < len(input); i++ {
		input[i] = gl.NewVariable(sample[i])
	}

	circuit := DebugBN254HashOrNoop84Circuit{}
	witness := DebugBN254HashOrNoop84Circuit{
		Input: input,
		ExpectedHash: [4]frontend.Variable{
			frontend.Variable(hash0),
			frontend.Variable(hash1),
			frontend.Variable(hash2),
			frontend.Variable(hash3),
		},
	}

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
