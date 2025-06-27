# Gnark Playground

A comprehensive demonstration of integrating [gnark](https://github.com/ConsenSys/gnark), a Go-based framework for zero-knowledge proofs, with C applications through CGo. This project specifically implements P256 ECDSA signature verification within zero-knowledge proofs using the Groth16 proving system.

## 🚀 Features

- **P256 ECDSA Verification**: Complete circuit implementation for verifying ECDSA signatures on the P256 elliptic curve
- **Groth16 Proof System**: Efficient zk-SNARK generation and verification using the Groth16 backend
- **Cross-Language Integration**: CGo wrapper enabling C applications to use gnark functionality
- **Persistent Storage**: Serialization support for proving keys, verifying keys, and circuit definitions
- **Performance Optimized**: ~1.2s proof generation, ~3ms verification time

## 📋 Prerequisites

- Go 1.19 or higher
- GCC compiler (for CGo compilation)
- Make utility

## 🛠️ Installation & Setup

### 1. Generate Core Circuits

Generate the proving key, verifying key, and circuit files:

```bash
go run generate_input.go
```

This command will:
- Create the primary zk-SNARK circuits
- Generate sample input for testing
- Perform an initial proof generation and verification
- Output circuit files: `r1cs.bin`, `proving_key.bin`, `verifying_key.bin`, `witness_input.json`

### 2. Build CGo Bindings

```bash
go run ecdsa_verifier.go
```

This separates the proving process from circuit setup and demonstrates:
- Loading previously generated circuits from disk
- Generating random P256 ECDSA inputs
- Creating proofs using the loaded circuit artifacts

### 3. Compile Shared Library

```bash
make
```

Generates the C-compatible shared library using CGo wrappers for integration with C applications.

## 🧪 Testing

### Circuit Generation & Verification

Running `go run generate_input.go` should produce output similar to:

```
--- Performing compliance check (Prove & Verify within generate_input.go) ---
10:40:31 DBG constraint system solver done nbConstraints=151191 took=200.657492
10:40:32 DBG prover done acceleration=none backend=groth16 curve=bn254 nbConstraints=151191 took=1036.03961
Compliance check: Proof generated (1236.0ms).
10:40:32 DBG verifier done backend=groth16 curve=bn254 took=3.144212
Compliance check: Verification SUCCEEDED (3.0ms)!

✅ Compliance check PASSED. Generated inputs are valid.
```

### CGo Integration Testing

The `ecdsa_verifier.go` test demonstrates two key scenarios:

**Test 1: Proof verification with pre-generated inputs**
```
=== Test 1: RunProofVerification ===
✓ RunProofVerification succeeded
```

**Test 2: Dynamic input generation and verification**
```
=== Test 2: RunProofVerificationWithInputs ===
✓ RunProofVerificationWithInputs succeeded
```

### C Library Testing

After building, test the generated libraries:

```bash
./test_c_shared    # Test shared library integration
./test_c_static    # Test static library integration
```

## 📁 Generated Files

| File | Description |
|------|-------------|
| `r1cs.bin` | Compiled constraint system (151,191 constraints) |
| `proving_key.bin` | Groth16 proving key for proof generation |
| `verifying_key.bin` | Groth16 verifying key for proof verification |
| `witness_input.json` | Sample witness data for testing |

## 🔧 Usage Example

### Go Integration

```go
// Load circuit artifacts
r1cs := LoadR1CS("r1cs.bin")
pk := LoadProvingKey("proving_key.bin")
vk := LoadVerifyingKey("verifying_key.bin")

// Generate proof
proof := GenerateProof(pk, witness)

// Verify proof
isValid := VerifyProof(vk, proof, publicInputs)
```

### C Integration

```c
// Use the generated shared library
int result = verify_ecdsa_proof(msgHash, r, s, pubX, pubY);
if (result == 1) {
    printf("Proof verification successful!\n");
}
```

## ⚡ Performance Metrics

- **Circuit Size**: 151,191 constraints
- **Proof Generation**: ~1.2 seconds
- **Proof Verification**: ~3 milliseconds
- **Curve**: BN254 (for zk-SNARK operations)
- **ECDSA Curve**: P256

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────┐
│   Go Circuit    │───▶│ CGo Wrapper  │───▶│ C Library   │
│   (gnark)       │    │              │    │             │
└─────────────────┘    └──────────────┘    └─────────────┘
         │                       │                  │
         ▼                       ▼                  ▼
┌─────────────────┐    ┌──────────────┐    ┌─────────────┐
│ Circuit Files   │    │ Shared Lib   │    │ C App       │
│ (.bin, .json)   │    │ (.so/.dylib) │    │ Integration │
└─────────────────┘    └──────────────┘    └─────────────┘
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- [gnark](https://github.com/ConsenSys/gnark) - Zero-knowledge proof framework
- [Groth16](https://eprint.iacr.org/2016/260.pdf) - Efficient zk-SNARK construction
- P256 ECDSA - NIST standard elliptic curve cryptography

## 📚 Additional Resources

- [gnark Documentation](https://docs.gnark.consensys.net/)
- [Zero-Knowledge Proofs: An Illustrated Primer](https://blog.cryptographyengineering.com/2014/11/27/zero-knowledge-proofs-illustrated-primer/)
- [Understanding zk-SNARKs](https://blog.ethereum.org/2016/12/05/zksnarks-in-a-nutshell/)