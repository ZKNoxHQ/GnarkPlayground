package main

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	mimc_in_circuit "github.com/consensys/gnark/std/hash/mimc" // gnark circuit version
)

// Circuit using gnark's MiMC gadget
type MiMCCircuit struct {
	X   frontend.Variable
	Y   frontend.Variable
	Out frontend.Variable `gnark:",public"`
}

func (c *MiMCCircuit) Define(api frontend.API) error {
	h, _ := mimc_in_circuit.NewMiMC(api)
	h.Write(c.X)
	h.Write(c.Y)
	sum := h.Sum()
	api.AssertIsEqual(sum, c.Out)
	return nil
}

func main() {
	// OUTSIDE CIRCUIT: gnark-crypto mimc hash
	h := mimc.NewMiMC()
	var x, y fr.Element
	x.SetUint64(123)
	bytes_x := x.Bytes()
	y.SetUint64(456)
	bytes_y := y.Bytes()
	h.Write(bytes_x[:])
	h.Write(bytes_y[:])
	digest := h.Sum(nil)
	fmt.Printf("Outside circuit MiMC hash = %x\n", digest)

	// Convert digest bytes to big.Int (for passing to gnark circuit)
	digestInt := new(big.Int).SetBytes(digest)

	// Define circuit and compile
	var circuit MiMCCircuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	// Create witness with inputs and expected output
	assignment := MiMCCircuit{
		X:   123,
		Y:   456,
		Out: digestInt,
	}

	// Setup
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		panic(err)
	}

	witnessFull, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())

	if err != nil {
		panic(err)
	}

	publicWitness, err := witnessFull.Public()

	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		panic("proof verification failed: " + err.Error())
	}

	fmt.Println("Proof verified successfully")

}
