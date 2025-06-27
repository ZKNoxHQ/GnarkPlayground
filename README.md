
# Gnark Playground

This repository provides a demonstration of integrating gnark, a Go-based framework for writing zk-SNARKs, with C applications using a CGo wrapper. Specifically, it focuses on verifying P256 ECDSA signatures within a zero-knowledge proof.



## Features
- P256 ECDSA Verification: Implements a Gnark circuit for verifying ECDSA signatures on the P256 curve.

- Groth16 Proof System: Utilizes the Groth16 backend for zk-SNARK generation and verification.

- CGo Integration: Provides a Go-based CGo wrapper to expose the Gnark verification functionality as a C-compatible shared library.

-  Serializes and deserializes proving keys, verifying keys, and circuit definitions to/from disk for persistent storage and reuse.


## Install 


### Generate circuits (go only)

First generates the primary circuits
``` 
go run generate_input.go
``` 
It will generates the proving key, verifying key and circuit, generates an input for the prover, prove and verify it.

### Generate cGo bindings
``` 
go run ecdsa_verifier.go
``` 

The following command separates proving from the whole setUp of the circuit.
It generates random input for P256, and use the previously generated circuit to prove it.


### Generate shared Library
``` 
make
``` 
This command generates the C library using cGo wrappers


## Testing


### SetUp
The  "go run generate_input.go" shall generate and verify the proof:

``` 
--- Performing compliance check (Prove & Verify within generate_input.go) ---
10:40:31 DBG constraint system solver done nbConstraints=151191 took=200.657492
10:40:32 DBG prover done acceleration=none backend=groth16 curve=bn254 nbConstraints=151191 took=1036.03961
Compliance check: Proof generated (1236.0ms).
10:40:32 DBG verifier done backend=groth16 curve=bn254 took=3.144212
Compliance check: Verification SUCCEEDED (3.0ms)!
Compliance check PASSED. Generated inputs are valid.
Wrote r1cs.bin
Wrote proving_key.bin
Wrote verifying_key.bin
Wrote witness_input.json

All input files generated successfully for CGO wrapper.

--- Testing ReadFromFile and re-verification ---
Read r1cs.bin (Constraints: 151191)
Read proving_key.bin
Read verifying_key.bin
Read witness_input.json

--- Proving and Verifying with loaded artifacts ---
10:40:41 DBG constraint system solver done nbConstraints=151191 took=200.903957
10:40:42 DBG prover done acceleration=none backend=groth16 curve=bn254 nbConstraints=151191 took=1041.149071
Verification from loaded files: Proof generated (1242.0ms).
10:40:42 DBG verifier done backend=groth16 curve=bn254 took=3.046517
Verification from loaded files: Verification SUCCEEDED (3.0ms)!
ReadFromFile test PASSED. Loaded artifacts are valid and functional.
``` 


### Test proving

The ecdsa_verifier.go shall generates:

``` 
Testing cGO ECDSA Proof Verifier...

=== Test 1: RunProofVerification ===

--- Testing ReadFromFile and re-verification ---
Read r1cs.bin (Constraints: 151191)
Read proving_key.bin
Read verifying_key.bin
Read witness_input.json

--- ProveInput Data (for C interface reference) ---
MsgHash: beaaf37129e2e801ca360e226bce78c8c82ad08bf88e3250177e8e32cad17f8e
R:       216ab8f965b2a9a7096f9b09ef181d3749029e49b0058ea6e079835824ca8a02
S:       257661138b958bc742600a5c81f43dc9d7b907bfde330a1d0bbde3c479169794
PubX:    ae54bd0f6c8582270b6eb403a517ce624adf593b32539f9c6f7f526d5b6963f7
PubY:    449411692bd6cb37b7832a50de8d5654e8e180c86c5fa3aadc4efdbbd8908a2d
--- End ProveInput Data ---

--- Proving and Verifying with loaded artifacts ---
10:41:36 DBG constraint system solver done nbConstraints=151191 took=156.970667
10:41:37 DBG prover done acceleration=none backend=groth16 curve=bn254 nbConstraints=151191 took=494.455473
Proof generated (651.0ms).
10:41:37 DBG verifier done backend=groth16 curve=bn254 took=1.198719
Verification SUCCEEDED (1.0ms)!
ReadFromFile test PASSED. Loaded artifacts are valid and functional.
✓ RunProofVerification succeeded

=== Test 2: RunProofVerificationWithInputs ===

--- Generated NEW VALID ECDSA ProveInput for this execution ---
MsgHash: 91b25f28fdc02ae7dde45a8a2097e30d35ca4280a265fccc8dca478f1bde6295
R:       4108b41531fc40d935fec82a46f23d1b1e3a63b7f82ba1452e2b9d5f31f9b170
S:       d5a4c2d80d6d8c4ee8a011b368435b3e67cc978e9290144b7ac22a275fe14365
PubX:    9070ff80e93a1b3353de9585ced81c20a61c4cd59d51304470d0e678170be236
PubY:    fce84186137d934e7293e957fbbf87b1a9050de11a40ac6b9bc5e910692af074
--- Copy these NEW VALID values for your C program ---
--- Note: These are cryptographically valid ECDSA signature + key pair ---
10:41:39 DBG constraint system solver done nbConstraints=151191 took=129.913174
10:41:40 DBG prover done acceleration=none backend=groth16 curve=bn254 nbConstraints=151191 took=719.19839
10:41:40 DBG verifier done backend=groth16 curve=bn254 took=2.772141
✓ RunProofVerificationWithInputs succeeded

cGO ECDSA Proof Verifier tests completed.
``` 

The command also generated to executables that shall provide C testing:

``` 
./test_c_shared
/test_c_static
``` 