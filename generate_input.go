package main

import (
	"bytes"
	cryptoecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"time" // Added for performance timing

	"github.com/consensys/gnark-crypto/ecc"
	mimcOut "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// EcdsaCircuit defines the circuit structure as provided by you.
type EcdsaCircuitWithCommitment[T, S emulated.FieldParams] struct {
	// Public inputs
	Sig gnarkecdsa.Signature[S] `gnark:",public"`
	Msg emulated.Element[S]     `gnark:",public"`

	// Commitment to public key (public)
	PubKeyCommitment frontend.Variable `gnark:",public"` //emulated.Element[S] `gnark:",public"`

	// Private inputs (witness)
	Pub   gnarkecdsa.PublicKey[T, S] // Private: the actual public key
	Nonce emulated.Element[T]        // Private: random nonce for commitment
}

func (c *EcdsaCircuitWithCommitment[T, S]) Define(api frontend.API) error {
	// 1. Verify the ECDSA signature
	curveParams := sw_emulated.GetCurveParams[T]()
	c.Pub.Verify(api, curveParams, &c.Msg, &c.Sig)

	// 2. Verify the commitment to the public key
	// commitment = MiMC(pubX || pubY || nonce)
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Hash the public key coordinates and nonce
	mimc.Write(c.Pub.X.Limbs...)
	mimc.Write(c.Pub.Y.Limbs...)
	mimc.Write(c.Nonce.Limbs...)
	computedCommitment := mimc.Sum()

	// Assert that the computed commitment matches the public commitment
	api.AssertIsEqual(c.PubKeyCommitment, computedCommitment)

	return nil
}

// ProveInputEcdsa struct for JSON serialization of witness inputs.
type ProveInputEcdsaWithCommitment struct {
	MsgHash          string `json:"msgHash"` // Hex string of the message hash
	R                string `json:"r"`       // Hex string of signature R
	S                string `json:"s"`       // Hex string of signature S
	PubX             string `json:"pubX"`    // Hex string of public key X
	PubY             string `json:"pubY"`    // Hex string of public key Y
	PubKeyCommitment string `json:"pubCom"`  // Hex string of public key commitment
	Nonce            string `json:"nonce"`   // Hex string of nonce
}

func main() {
	fmt.Println("--- Generating ECDSA circuit inputs and performing compliance check ---")

	// 1. Off-circuit ECDSA signature generation (to get inputs for the circuit)
	privKey, _ := cryptoecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey := privKey.PublicKey

	msg := []byte("testing ECDSA with gnark-CGO")
	msgHash := sha256.Sum256(msg)
	sigBin, _ := privKey.Sign(rand.Reader, msgHash[:], nil)

	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	inputSig := cryptobyte.String(sigBin)
	if !inputSig.ReadASN1(&inner, asn1.SEQUENCE) ||
		!inputSig.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		fmt.Println("Error: invalid ASN.1 signature format for off-circuit signature")
		os.Exit(1)
	}

	// 2. Generate commitment to public key using MiMC
	// Generate a random nonce for the commitment
	upperBound := new(big.Int).Lsh(big.NewInt(1), 256) // 2^256
	nonce, err := rand.Int(rand.Reader, upperBound)
	if err != nil {
		fmt.Println("Failed to create the nonce: %w", err)
	}

	// Create MiMC hasher (using bn254 curve params for compatibility with gnark)
	hasher := mimcOut.NewMiMC()

	// Hash: MiMC(pubX || pubY || nonce)
	hasher.Write(publicKey.X.Bytes())
	hasher.Write(publicKey.Y.Bytes())
	hasher.Write(nonce.Bytes())
	commitment := hasher.Sum(nil)

	// Convert commitment to big.Int
	commitmentBigInt := new(big.Int).SetBytes(commitment)

	// 3. Prepare JSON input for proving
	proveInput := ProveInputEcdsaWithCommitment{
		MsgHash:          hex.EncodeToString(msgHash[:]),
		R:                hex.EncodeToString(r.Bytes()),
		S:                hex.EncodeToString(s.Bytes()),
		PubX:             hex.EncodeToString(publicKey.X.Bytes()),
		PubY:             hex.EncodeToString(publicKey.Y.Bytes()),
		Nonce:            hex.EncodeToString(nonce.Bytes()),
		PubKeyCommitment: hex.EncodeToString(commitment),
	}

	proveInputJSON, err := json.MarshalIndent(proveInput, "", " ")
	if err != nil {
		fmt.Printf("Error marshaling prove input JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Prove input JSON:\n%s\n", proveInputJSON)

	// 4. Compile the circuit
	circuit := EcdsaCircuitWithCommitment[emulated.P256Fp, emulated.P256Fr]{}
	fmt.Printf("Compiling circuit...\n")
	ecdsaR1CS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("Error compiling ECDSA circuit: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("BN254 circuit compiled with %d constraints\n",
		ecdsaR1CS.GetNbConstraints())
	fmt.Printf("CIRCUIT COMPILED\n")

	// 5. Perform Groth16 setup
	fmt.Printf("Starting Groth16 setup...\n")
	ecdsaPK, ecdsaVK, err := groth16.Setup(ecdsaR1CS)
	if err != nil {
		fmt.Printf("Error during Groth16 setup for ECDSA: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Setup done.\n")

	// 6. Create the full witness for the circuit (includes private and public parts)
	witnessCircuit := EcdsaCircuitWithCommitment[emulated.P256Fp, emulated.P256Fr]{
		Sig: ecdsa.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		},
		Msg:              emulated.ValueOf[emulated.P256Fr](msgHash[:]),
		PubKeyCommitment: commitmentBigInt, // TODO SIMON IS IT SECURE?
		Pub: ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](publicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](publicKey.Y),
		},
		Nonce: emulated.ValueOf[emulated.P256Fp](nonce),
	}
	witnessFull, err := frontend.NewWitness(&witnessCircuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("Error creating full witness: %v\n", err)
		os.Exit(1)
	}
	publicWitness, err := witnessFull.Public() // Extract public parts for verification
	if err != nil {
		fmt.Printf("Error getting public witness: %v\n", err)
		os.Exit(1)
	}

	// 7. Perform a compliance check: Prove and Verify
	fmt.Println("\n--- Performing compliance check (Prove & Verify within generate_input.go) ---")

	// Prove
	startProve := time.Now()
	proof, err := groth16.Prove(ecdsaR1CS, ecdsaPK, witnessFull)
	if err != nil {
		fmt.Printf("Compliance check: Error generating proof: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Compliance check: Proof generated (%.1fms).\n", float64(time.Since(startProve).Milliseconds()))

	// Verify
	startVerify := time.Now()
	err = groth16.Verify(proof, ecdsaVK, publicWitness)
	if err != nil {
		fmt.Printf("Compliance check: Verification FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Compliance check: Verification SUCCEEDED (%.1fms)!\n", float64(time.Since(startVerify).Milliseconds()))
	fmt.Println("Compliance check PASSED. Generated inputs are valid.")

	// 8. Write outputs to files (same as before)
	writeToFile("r1cs.bin", ecdsaR1CS)
	writeToFile("proving_key.bin", ecdsaPK)
	writeToFile("verifying_key.bin", ecdsaVK)
	writeToFile("witness_input.json", bytes.NewReader(proveInputJSON))

	fmt.Println("\nAll input files generated successfully for CGO wrapper.")

	// 9. Test the ReadFromFile functionality
	testReadFromFile()

	fmt.Println("\nAll input files generated successfully for CGO wrapper.")

}

// writeToFile is a helper to serialize and write gnark objects or byte readers to files.
func writeToFile(filename string, data interface{}) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating file %s: %v\n", filename, err)
		os.Exit(1)
	}
	defer file.Close()

	switch v := data.(type) {
	case io.WriterTo:
		_, err = v.WriteTo(file)
	case *bytes.Reader: // For the JSON input
		_, err = v.WriteTo(file)
	default:
		err = fmt.Errorf("unsupported type for writing to file")
	}

	if err != nil {
		fmt.Printf("Error writing to file %s: %v\n", filename, err)
		os.Exit(1)
	}
	fmt.Printf("Wrote %s\n", filename)
}

// testReadFromFile reads the generated files back and performs a verification.
func testReadFromFile() {
	fmt.Println("\n--- Testing ReadFromFile and re-verification ---")

	// 1. Read back the compiled circuit
	loadedR1CS := groth16.NewCS(ecc.BN254)
	err := readFromFile("r1cs.bin", loadedR1CS)
	if err != nil {
		fmt.Printf("Error reading r1cs.bin: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Read r1cs.bin (Constraints: %d)\n", loadedR1CS.GetNbConstraints())

	// 2. Read back the proving key
	loadedPK := groth16.NewProvingKey(ecc.BN254)
	err = readFromFile("proving_key.bin", loadedPK)
	if err != nil {
		fmt.Printf("Error reading proving_key.bin: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Read proving_key.bin")

	// 3. Read back the verifying key
	loadedVK := groth16.NewVerifyingKey(ecc.BN254)
	err = readFromFile("verifying_key.bin", loadedVK)
	if err != nil {
		fmt.Printf("Error reading verifying_key.bin: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Read verifying_key.bin")

	// 4. Read back the prove input JSON
	var loadedProveInput ProveInputEcdsaWithCommitment
	err = readFromFile("witness_input.json", &loadedProveInput)
	if err != nil {
		fmt.Printf("Error reading witness_input.json: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Read witness_input.json")

	// Decode hex strings back to big.Int and byte slices for witness construction
	rBytes, err := hex.DecodeString(loadedProveInput.R)
	if err != nil {
		fmt.Printf("Error decoding R hex: %v\n", err)
		os.Exit(1)
	}
	sBytes, err := hex.DecodeString(loadedProveInput.S)
	if err != nil {
		fmt.Printf("Error decoding S hex: %v\n", err)
		os.Exit(1)
	}
	msgHashBytes, err := hex.DecodeString(loadedProveInput.MsgHash)
	if err != nil {
		fmt.Printf("Error decoding MsgHash hex: %v\n", err)
		os.Exit(1)
	}
	pubKeyCommitmentBytes, err := hex.DecodeString(loadedProveInput.PubKeyCommitment)
	NonceBytes, err := hex.DecodeString(loadedProveInput.Nonce)
	pubXBytes, err := hex.DecodeString(loadedProveInput.PubX)
	if err != nil {
		fmt.Printf("Error decoding PubX hex: %v\n", err)
		os.Exit(1)
	}
	pubYBytes, err := hex.DecodeString(loadedProveInput.PubY)
	if err != nil {
		fmt.Printf("Error decoding PubY hex: %v\n", err)
		os.Exit(1)
	}

	rLoaded := new(big.Int).SetBytes(rBytes)
	sLoaded := new(big.Int).SetBytes(sBytes)
	pubXLoaded := new(big.Int).SetBytes(pubXBytes)
	pubYLoaded := new(big.Int).SetBytes(pubYBytes)
	NonceLoaded := new(big.Int).SetBytes(NonceBytes)

	// 5. Create a new witness using the loaded input data
	witnessCircuitLoaded := EcdsaCircuitWithCommitment[emulated.P256Fp, emulated.P256Fr]{
		Sig: gnarkecdsa.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](rLoaded),
			S: emulated.ValueOf[emulated.P256Fr](sLoaded),
		},
		Msg: emulated.ValueOf[emulated.P256Fr](msgHashBytes),
		Pub: gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](pubXLoaded),
			Y: emulated.ValueOf[emulated.P256Fp](pubYLoaded),
		},
		PubKeyCommitment: emulated.ValueOf[emulated.P256Fr](pubKeyCommitmentBytes),
		Nonce:            emulated.ValueOf[emulated.P256Fp](NonceLoaded),
	}
	witnessFullLoaded, err := frontend.NewWitness(&witnessCircuitLoaded, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("Error creating full witness from loaded data: %v\n", err)
		os.Exit(1)
	}
	publicWitnessLoaded, err := witnessFullLoaded.Public()
	if err != nil {
		fmt.Printf("Error getting public witness from loaded data: %v\n", err)
		os.Exit(1)
	}

	// 6. Perform a new proof and verification using the loaded artifacts
	fmt.Println("\n--- Proving and Verifying with loaded artifacts ---")

	// Prove
	startProveLoaded := time.Now()
	proofLoaded, err := groth16.Prove(loadedR1CS, loadedPK, witnessFullLoaded)
	if err != nil {
		fmt.Printf("Verification from loaded files: Error generating proof: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Verification from loaded files: Proof generated (%.1fms).\n", float64(time.Since(startProveLoaded).Milliseconds()))

	// Verify
	startVerifyLoaded := time.Now()
	err = groth16.Verify(proofLoaded, loadedVK, publicWitnessLoaded)
	if err != nil {
		fmt.Printf("Verification from loaded files: Verification FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Verification from loaded files: Verification SUCCEEDED (%.1fms)!\n", float64(time.Since(startVerifyLoaded).Milliseconds()))
	fmt.Println("ReadFromFile test PASSED. Loaded artifacts are valid and functional.")
}
