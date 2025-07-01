package main

/*
#include <stdlib.h>
#include <string.h>

typedef struct {
    char* error_msg;
    int success;
} ProofResult;

typedef struct {
    char* msgHash;
    char* r;
    char* s;
    char* pubX;
    char* pubY;
} ProveInput;
*/
import "C"

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	mimcOut "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc" // use correct curve
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

// Helper function to generate a valid ECDSA signature and key pair
func generateValidECDSAData() (*ProveInputEcdsaWithCommitment, error) {
	// Generate a new private key on P-256 curve
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	publicKey := privateKey.PublicKey

	// Generate a random message
	message := make([]byte, 32)
	_, err = rand.Read(message)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random message: %w", err)
	}

	// Hash the message
	hash := sha256.Sum256(message)

	// Sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// Generate a random nonce for the commitment
	upperBound := new(big.Int).Lsh(big.NewInt(1), 256) // 2^256
	nonce, err := rand.Int(rand.Reader, upperBound)
	if err != nil {
		return nil, fmt.Errorf("Failed to create the nonce: %w", err)
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

	// Create ProveInputEcdsa with proper values
	proveInput := &ProveInputEcdsaWithCommitment{
		MsgHash:          hex.EncodeToString(hash[:]),
		R:                hex.EncodeToString(r.Bytes()),
		S:                hex.EncodeToString(s.Bytes()),
		PubX:             hex.EncodeToString(privateKey.PublicKey.X.Bytes()),
		PubY:             hex.EncodeToString(privateKey.PublicKey.Y.Bytes()),
		PubKeyCommitment: hex.EncodeToString(commitmentBigInt.Bytes()),
		Nonce:            hex.EncodeToString(nonce.Bytes()),
	}

	// Verify the signature is correct (sanity check)
	if !ecdsa.Verify(&privateKey.PublicKey, hash[:], r, s) {
		return nil, fmt.Errorf("generated signature verification failed")
	}

	return proveInput, nil
}

// Helper function to create a variant of the original input with valid ECDSA data
func createVariantProveInput(original *ProveInputEcdsaWithCommitment) *ProveInputEcdsaWithCommitment {
	// Generate a completely new valid ECDSA signature and key pair
	variant, err := generateValidECDSAData()
	if err != nil {
		fmt.Printf("Warning: Failed to generate valid ECDSA data, using original: %v\n", err)
		// If generation fails, add timestamp to original to make it different
		timestamp := fmt.Sprintf("%x", time.Now().UnixNano())
		return &ProveInputEcdsaWithCommitment{
			MsgHash:          original.MsgHash[:50] + timestamp[:14], // Replace last 14 chars with timestamp
			R:                original.R,
			S:                original.S,
			PubX:             original.PubX,
			PubY:             original.PubY,
			PubKeyCommitment: original.PubKeyCommitment,
			Nonce:            original.Nonce,
		}
	}

	return variant
}
func cStringToGoString(cStr *C.char) string {
	if cStr == nil {
		return ""
	}
	return C.GoString(cStr)
}

// Helper function to convert Go string to C string (caller must free)
func goStringToCString(goStr string) *C.char {
	return C.CString(goStr)
}

// Helper function to free C string
func freeCString(cStr *C.char) {
	if cStr != nil {
		C.free(unsafe.Pointer(cStr))
	}
}

// Core proof generation and verification logic
func performProofVerification() error {
	fmt.Println("\n--- Testing ReadFromFile and re-verification ---")

	// 1. Read back the compiled circuit
	loadedR1CS := groth16.NewCS(ecc.BN254)
	err := readFromFile("r1cs.bin", loadedR1CS)
	if err != nil {
		return fmt.Errorf("error reading r1cs.bin: %w", err)
	}
	fmt.Printf("Read r1cs.bin (Constraints: %d)\n", loadedR1CS.GetNbConstraints())

	// 2. Read back the proving key
	loadedPK := groth16.NewProvingKey(ecc.BN254)
	err = readFromFile("proving_key.bin", loadedPK)
	if err != nil {
		return fmt.Errorf("error reading proving_key.bin: %w", err)
	}
	fmt.Println("Read proving_key.bin")

	// 3. Read back the verifying key
	loadedVK := groth16.NewVerifyingKey(ecc.BN254)
	err = readFromFile("verifying_key.bin", loadedVK)
	if err != nil {
		return fmt.Errorf("error reading verifying_key.bin: %w", err)
	}
	fmt.Println("Read verifying_key.bin")

	// 4. Read back the prove input JSON
	var loadedProveInput ProveInputEcdsaWithCommitment
	err = readFromFile("witness_input.json", &loadedProveInput)
	if err != nil {
		return fmt.Errorf("error reading witness_input.json: %w", err)
	}
	fmt.Println("Read witness_input.json")

	// Display the ProveInput data for reference
	fmt.Println("\n--- ProveInput Data (for C interface reference) ---")
	fmt.Printf("MsgHash: %s\n", loadedProveInput.MsgHash)
	fmt.Printf("R:       %s\n", loadedProveInput.R)
	fmt.Printf("S:       %s\n", loadedProveInput.S)
	fmt.Printf("PubX:    %s\n", loadedProveInput.PubX)
	fmt.Printf("PubY:    %s\n", loadedProveInput.PubY)
	fmt.Printf("PublicKeyCommitment:    %s\n", loadedProveInput.PubKeyCommitment)
	fmt.Printf("Nonce:    %s\n", loadedProveInput.Nonce)
	fmt.Println("--- End ProveInput Data ---")

	// Decode hex strings back to big.Int and byte slices
	rBytes, err := hex.DecodeString(loadedProveInput.R)
	if err != nil {
		return fmt.Errorf("error decoding R hex: %w", err)
	}
	sBytes, err := hex.DecodeString(loadedProveInput.S)
	if err != nil {
		return fmt.Errorf("error decoding S hex: %w", err)
	}
	msgHashBytes, err := hex.DecodeString(loadedProveInput.MsgHash)
	if err != nil {
		return fmt.Errorf("error decoding MsgHash hex: %w", err)
	}
	pubXBytes, err := hex.DecodeString(loadedProveInput.PubX)
	if err != nil {
		return fmt.Errorf("error decoding PubX hex: %w", err)
	}
	pubYBytes, err := hex.DecodeString(loadedProveInput.PubY)
	if err != nil {
		return fmt.Errorf("error decoding PubY hex: %w", err)
	}
	pubKeyCommitmentBytes, err := hex.DecodeString(loadedProveInput.PubKeyCommitment)
	if err != nil {
		return fmt.Errorf("error decoding PubKeyCommitment hex: %w", err)
	}
	NonceBytes, err := hex.DecodeString(loadedProveInput.Nonce)
	if err != nil {
		return fmt.Errorf("error decoding Nonce hex: %w", err)
	}

	rLoaded := new(big.Int).SetBytes(rBytes)
	sLoaded := new(big.Int).SetBytes(sBytes)
	pubXLoaded := new(big.Int).SetBytes(pubXBytes)
	pubYLoaded := new(big.Int).SetBytes(pubYBytes)
	pubKeyCommitmentLoaded := new(big.Int).SetBytes(pubKeyCommitmentBytes)
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
		PubKeyCommitment: emulated.ValueOf[emulated.P256Fp](pubKeyCommitmentLoaded),
		Nonce:            emulated.ValueOf[emulated.P256Fp](NonceLoaded),
	}

	witnessFullLoaded, err := frontend.NewWitness(&witnessCircuitLoaded, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("error creating full witness from loaded data: %w", err)
	}

	publicWitnessLoaded, err := witnessFullLoaded.Public()
	if err != nil {
		return fmt.Errorf("error getting public witness from loaded data: %w", err)
	}

	// 6. Perform proof and verification
	fmt.Println("\n--- Proving and Verifying with loaded artifacts ---")

	// Prove
	startProveLoaded := time.Now()
	proofLoaded, err := groth16.Prove(loadedR1CS, loadedPK, witnessFullLoaded)
	if err != nil {
		return fmt.Errorf("error generating proof: %w", err)
	}
	fmt.Printf("Proof generated (%.1fms).\n", float64(time.Since(startProveLoaded).Milliseconds()))

	// Verify
	startVerifyLoaded := time.Now()
	err = groth16.Verify(proofLoaded, loadedVK, publicWitnessLoaded)
	if err != nil {
		return fmt.Errorf("verification FAILED: %w", err)
	}
	fmt.Printf("Verification SUCCEEDED (%.1fms)!\n", float64(time.Since(startVerifyLoaded).Milliseconds()))
	fmt.Println("ReadFromFile test PASSED. Loaded artifacts are valid and functional.")

	return nil
}

// Core proof generation with custom inputs
func performProofVerificationWithInputs(proveInput *ProveInputEcdsaWithCommitment) error {
	// 1. Read back the compiled circuit
	loadedR1CS := groth16.NewCS(ecc.BN254)
	err := readFromFile("r1cs.bin", loadedR1CS)
	if err != nil {
		return fmt.Errorf("error reading r1cs.bin: %w", err)
	}

	// 2. Read back the proving key
	loadedPK := groth16.NewProvingKey(ecc.BN254)
	err = readFromFile("proving_key.bin", loadedPK)
	if err != nil {
		return fmt.Errorf("error reading proving_key.bin: %w", err)
	}

	// 3. Read back the verifying key
	loadedVK := groth16.NewVerifyingKey(ecc.BN254)
	err = readFromFile("verifying_key.bin", loadedVK)
	if err != nil {
		return fmt.Errorf("error reading verifying_key.bin: %w", err)
	}

	// Decode hex strings
	rBytes, err := hex.DecodeString(proveInput.R)
	if err != nil {
		return fmt.Errorf("error decoding R hex: %w", err)
	}
	sBytes, err := hex.DecodeString(proveInput.S)
	if err != nil {
		return fmt.Errorf("error decoding S hex: %w", err)
	}
	msgHashBytes, err := hex.DecodeString(proveInput.MsgHash)
	if err != nil {
		return fmt.Errorf("error decoding MsgHash hex: %w", err)
	}
	pubXBytes, err := hex.DecodeString(proveInput.PubX)
	if err != nil {
		return fmt.Errorf("error decoding PubX hex: %w", err)
	}
	pubYBytes, err := hex.DecodeString(proveInput.PubY)
	if err != nil {
		return fmt.Errorf("error decoding PubY hex: %w", err)
	}
	pubKeyCommitmentBytes, err := hex.DecodeString(proveInput.PubKeyCommitment)
	if err != nil {
		return fmt.Errorf("error decoding PubKeyCommitment hex: %w", err)
	}
	NonceBytes, err := hex.DecodeString(proveInput.Nonce)
	if err != nil {
		return fmt.Errorf("error decoding Nonce hex: %w", err)
	}

	rLoaded := new(big.Int).SetBytes(rBytes)
	sLoaded := new(big.Int).SetBytes(sBytes)
	pubXLoaded := new(big.Int).SetBytes(pubXBytes)
	pubYLoaded := new(big.Int).SetBytes(pubYBytes)
	pubKeyCommitmentLoaded := new(big.Int).SetBytes(pubKeyCommitmentBytes)
	NonceLoaded := new(big.Int).SetBytes(NonceBytes)

	// Create witness
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
		PubKeyCommitment: emulated.ValueOf[emulated.P256Fp](pubKeyCommitmentLoaded),
		Nonce:            emulated.ValueOf[emulated.P256Fp](NonceLoaded),
	}

	witnessFullLoaded, err := frontend.NewWitness(&witnessCircuitLoaded, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("error creating full witness: %w", err)
	}

	publicWitnessLoaded, err := witnessFullLoaded.Public()
	if err != nil {
		return fmt.Errorf("error getting public witness: %w", err)
	}

	// Prove
	proofLoaded, err := groth16.Prove(loadedR1CS, loadedPK, witnessFullLoaded)
	if err != nil {
		return fmt.Errorf("error generating proof: %w", err)
	}

	// Verify
	err = groth16.Verify(proofLoaded, loadedVK, publicWitnessLoaded)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	return nil
}

//export RunProofVerification
func RunProofVerification() C.ProofResult {
	err := performProofVerification()
	if err != nil {
		return C.ProofResult{
			error_msg: goStringToCString(err.Error()),
			success:   0,
		}
	}
	return C.ProofResult{
		error_msg: nil,
		success:   1,
	}
}

//export RunProofVerificationWithInputs
func RunProofVerificationWithInputs(input C.ProveInputEcdsaWithCommitment) C.ProofResult {
	// Convert C input to Go struct
	proveInput := &ProveInputEcdsaWithCommitment{
		MsgHash:          cStringToGoString(input.msgHash),
		R:                cStringToGoString(input.r),
		S:                cStringToGoString(input.s),
		PubX:             cStringToGoString(input.pubX),
		PubY:             cStringToGoString(input.pubY),
		PubKeyCommitment: cStringToGoString(input.PubKeyCommitment),
		Nonce:            cStringToGoString(input.Nonce),
	}

	err := performProofVerificationWithInputs(proveInput)
	if err != nil {
		return C.ProofResult{
			error_msg: goStringToCString(err.Error()),
			success:   0,
		}
	}
	return C.ProofResult{
		error_msg: nil,
		success:   1,
	}
}

//export FreeProofResult
func FreeProofResult(result C.ProofResult) {
	if result.error_msg != nil {
		freeCString(result.error_msg)
	}
}

// // Go main function for testing
// func main() {
// 	// Test the C export functions
// 	fmt.Println("Testing cGO ECDSA Proof Verifier...")

// 	// Test 1: Run proof verification from files
// 	fmt.Println("\n=== Test 1: RunProofVerification ===")
// 	result1 := RunProofVerification()
// 	if result1.success == 1 {
// 		fmt.Println("✓ RunProofVerification succeeded")
// 	} else {
// 		fmt.Printf("✗ RunProofVerification failed: %s\n", cStringToGoString(result1.error_msg))
// 	}
// 	FreeProofResult(result1)

// 	// Test 2: Run proof verification with custom inputs (generating variant input)
// 	fmt.Println("\n=== Test 2: RunProofVerificationWithInputs ===")
// 	var loadedProveInput ProveInputEcdsaWithCommitment
// 	err := readFromFile("witness_input.json", &loadedProveInput)
// 	if err != nil {
// 		fmt.Printf("✗ Error reading witness_input.json for test: %v\n", err)
// 		return
// 	}

// 	// Generate a variant input for this execution
// 	variantProveInput := createVariantProveInput(&loadedProveInput)

// 	fmt.Println("\n--- Generated NEW VALID ECDSA ProveInput for this execution ---")
// 	fmt.Printf("MsgHash: %s\n", variantProveInput.MsgHash)
// 	fmt.Printf("R:       %s\n", variantProveInput.R)
// 	fmt.Printf("S:       %s\n", variantProveInput.S)
// 	fmt.Printf("PubX:    %s\n", variantProveInput.PubX)
// 	fmt.Printf("PubY:    %s\n", variantProveInput.PubY)
// 	fmt.Println("--- Copy these NEW VALID values for your C program ---")
// 	fmt.Println("--- Note: These are cryptographically valid ECDSA signature + key pair ---")

// 	// Convert to C input using the variant data
// 	cInput := C.ProveInput{
// 		msgHash: goStringToCString(variantProveInput.MsgHash),
// 		r:       goStringToCString(variantProveInput.R),
// 		s:       goStringToCString(variantProveInput.S),
// 		pubX:    goStringToCString(variantProveInput.PubX),
// 		pubY:    goStringToCString(variantProveInput.PubY),
// 	}

// 	result2 := RunProofVerificationWithInputs(cInput)
// 	if result2.success == 1 {
// 		fmt.Println("✓ RunProofVerificationWithInputs succeeded")
// 	} else {
// 		fmt.Printf("✗ RunProofVerificationWithInputs failed: %s\n", cStringToGoString(result2.error_msg))
// 	}

// 	// Clean up
// 	freeCString(cInput.msgHash)
// 	freeCString(cInput.r)
// 	freeCString(cInput.s)
// 	freeCString(cInput.pubX)
// 	freeCString(cInput.pubY)
// 	FreeProofResult(result2)

// 	fmt.Println("\ncGO ECDSA Proof Verifier tests completed.")
// }
