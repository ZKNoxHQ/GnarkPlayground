#ifndef CGO_ECDSA_VERIFIER_H
#define CGO_ECDSA_VERIFIER_H

#ifdef __cplusplus
extern "C" {
#endif

// Result structure for proof operations
typedef struct {
    char* error_msg;  // Error message (NULL if success)
    int success;      // 1 for success, 0 for failure
} ProofResult;

// Input structure for proof verification
typedef struct {
    char* msgHash;    // Hex string of the message hash
    char* r;          // Hex string of signature R
    char* s;          // Hex string of signature S
    char* pubX;       // Hex string of public key X coordinate
    char* pubY;       // Hex string of public key Y coordinate
} ProveInput;

// Function declarations
// Run proof verification using files (r1cs.bin, proving_key.bin, verifying_key.bin, witness_input.json)
ProofResult RunProofVerification();

// Run proof verification with custom inputs
ProofResult RunProofVerificationWithInputs(ProveInput input);

// Free memory allocated for ProofResult
void FreeProofResult(ProofResult result);

#ifdef __cplusplus
}
#endif

#endif // CGO_ECDSA_VERIFIER_H