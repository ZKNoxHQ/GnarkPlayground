#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ecdsa_verifier.h"

int main() {
    printf("Testing C interface to ECDSA Proof Verifier...\n");
    
    // Test 1: Run proof verification from files
    printf("\n=== Test 1: Proof verification from files ===\n");
    ProofResult result1 = RunProofVerification();
    
    if (result1.success) {
        printf("✓ Proof verification from files succeeded!\n");
    } else {
        printf("✗ Proof verification from files failed: %s\n", 
               result1.error_msg ? result1.error_msg : "Unknown error");
    }
    FreeProofResult(result1);
    
    // Test 2: Run proof verification with custom inputs
    printf("\n=== Test 2: Proof verification with custom inputs ===\n");
    
    // Example inputs (these should be replaced with actual values)
    ProveInput input = {
        .msgHash = "beaaf37129e2e801ca360e226bce78c8c82ad08bf88e3250177e8e32cad17f8e",
        .r = "d5675d2bf43d09c689c1c5f080467c40493ecfad7b8a9753ed4019615913c52b",
        .s = "9f6c5744183080ed5da9d3c1dacea9db10c07d4721dfe4aba8e217720635e3df",
        .pubX = "ec2a78c1dcde84326c812a7666a9167022ad2b388035d8fdd97b495939ce7174",
        .pubY = "dee8b2f2861a1bee29932861deb5e045580d3bbe1592d5aa1bbbe7322f2396e9"
    };
    
    ProofResult result2 = RunProofVerificationWithInputs(input);
    
    if (result2.success) {
        printf("✓ Proof verification with custom inputs succeeded!\n");
    } else {
        printf("✗ Proof verification with custom inputs failed: %s\n", 
               result2.error_msg ? result2.error_msg : "Unknown error");
    }
    FreeProofResult(result2);
    
    printf("\nC interface tests completed.\n");
    return 0;
}
