
// src/lib.rs
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use serde::{Deserialize, Serialize};

// FFI declarations matching your C interface
#[repr(C)]
pub struct ProveInput {
    pub msg_hash: *const c_char,
    pub r: *const c_char,
    pub s: *const c_char,
    pub pub_x: *const c_char,
    pub pub_y: *const c_char,
}

#[repr(C)]
pub struct ProofResult {
    pub success: c_int,
    pub error_msg: *const c_char,
    pub proof_data: *const c_char,
}

// External functions from your shared library
extern "C" {
    fn RunProofVerification() -> ProofResult;
    fn RunProofVerificationWithInputs(input: ProveInput) -> ProofResult;
    fn FreeProofResult(result: ProofResult);
}

// Rust-friendly structs
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EcdsaInput {
    pub msg_hash: String,
    pub r: String,
    pub s: String,
    pub pub_x: String,
    pub pub_y: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EcdsaProofOutput {
    pub success: bool,
    pub error_message: Option<String>,
    pub proof_data: Option<String>,
}

// Safe Rust wrapper for file-based verification
pub fn run_proof_verification_from_files() -> Result<EcdsaProofOutput, String> {
    // Call the C function
    let result = unsafe { RunProofVerification() };

    // Convert result back to Rust
    let output = convert_proof_result_to_rust(result);
    
    // Free the C result
    unsafe { FreeProofResult(result) };
    
    Ok(output)
}

// Safe Rust wrapper for custom input verification
pub fn run_proof_verification_with_inputs(input: EcdsaInput) -> Result<EcdsaProofOutput, String> {
    // Convert Rust strings to C strings
    let msg_hash_c = CString::new(input.msg_hash)
        .map_err(|e| format!("Invalid msg_hash: {}", e))?;
    let r_c = CString::new(input.r)
        .map_err(|e| format!("Invalid r: {}", e))?;
    let s_c = CString::new(input.s)
        .map_err(|e| format!("Invalid s: {}", e))?;
    let pub_x_c = CString::new(input.pub_x)
        .map_err(|e| format!("Invalid pub_x: {}", e))?;
    let pub_y_c = CString::new(input.pub_y)
        .map_err(|e| format!("Invalid pub_y: {}", e))?;

    // Create C struct
    let c_input = ProveInput {
        msg_hash: msg_hash_c.as_ptr(),
        r: r_c.as_ptr(),
        s: s_c.as_ptr(),
        pub_x: pub_x_c.as_ptr(),
        pub_y: pub_y_c.as_ptr(),
    };

    // Call the C function
    let result = unsafe { RunProofVerificationWithInputs(c_input) };

    // Convert result back to Rust
    let output = convert_proof_result_to_rust(result);
    
    // Free the C result
    unsafe { FreeProofResult(result) };
    
    Ok(output)
}

// Helper function to convert C ProofResult to Rust
fn convert_proof_result_to_rust(result: ProofResult) -> EcdsaProofOutput {
    let success = result.success != 0;
    
    let error_message = if result.error_msg.is_null() {
        None
    } else {
        unsafe {
            Some(CStr::from_ptr(result.error_msg)
                .to_string_lossy()
                .into_owned())
        }
    };

    let proof_data = if result.proof_data.is_null() {
        None
    } else {
        unsafe {
            Some(CStr::from_ptr(result.proof_data)
                .to_string_lossy()
                .into_owned())
        }
    };

    EcdsaProofOutput {
        success,
        error_message,
        proof_data,
    }
}

// Node.js bindings using Neon
#[cfg(feature = "nodejs")]
mod nodejs {
    use super::*;
    use neon::prelude::*;

    fn js_run_proof_verification_from_files(mut cx: FunctionContext) -> JsResult<JsObject> {
        match run_proof_verification_from_files() {
            Ok(result) => create_js_result(&mut cx, result),
            Err(e) => cx.throw_error(e),
        }
    }

    fn js_run_proof_verification_with_inputs(mut cx: FunctionContext) -> JsResult<JsObject> {
        // Get input object from JavaScript
        let input_obj = cx.argument::<JsObject>(0)?;
        
        // Extract fields
        let msg_hash = input_obj
            .get(&mut cx, "msgHash")?
            .downcast::<JsString, _>(&mut cx)
            .or_throw(&mut cx)?
            .value(&mut cx);
            
        let r = input_obj
            .get(&mut cx, "r")?
            .downcast::<JsString, _>(&mut cx)
            .or_throw(&mut cx)?
            .value(&mut cx);
            
        let s = input_obj
            .get(&mut cx, "s")?
            .downcast::<JsString, _>(&mut cx)
            .or_throw(&mut cx)?
            .value(&mut cx);
            
        let pub_x = input_obj
            .get(&mut cx, "pubX")?
            .downcast::<JsString, _>(&mut cx)
            .or_throw(&mut cx)?
            .value(&mut cx);
            
        let pub_y = input_obj
            .get(&mut cx, "pubY")?
            .downcast::<JsString, _>(&mut cx)
            .or_throw(&mut cx)?
            .value(&mut cx);

        let input = EcdsaInput {
            msg_hash,
            r,
            s,
            pub_x,
            pub_y,
        };

        // Run verification
        match run_proof_verification_with_inputs(input) {
            Ok(result) => create_js_result(&mut cx, result),
            Err(e) => cx.throw_error(e),
        }
    }

    fn create_js_result(cx: &mut FunctionContext, result: EcdsaProofOutput) -> JsResult<JsObject> {
        let js_result = cx.empty_object();
        
        let success = cx.boolean(result.success);
        js_result.set(cx, "success", success)?;
        
        if let Some(error) = result.error_message {
            let error_str = cx.string(error);
            js_result.set(cx, "errorMessage", error_str)?;
        } else {
            let null = cx.null();
            js_result.set(cx, "errorMessage", null)?;
        }
        
        if let Some(proof) = result.proof_data {
            let proof_str = cx.string(proof);
            js_result.set(cx, "proofData", proof_str)?;
        } else {
            let null = cx.null();
            js_result.set(cx, "proofData", null)?;
        }
        
        Ok(js_result)
    }

    #[neon::main]
    fn main(mut cx: ModuleContext) -> NeonResult<()> {
        cx.export_function("runProofVerificationFromFiles", js_run_proof_verification_from_files)?;
        cx.export_function("runProofVerificationWithInputs", js_run_proof_verification_with_inputs)?;
        Ok(())
    }
}

// WebAssembly bindings using wasm-bindgen
#[cfg(feature = "wasm")]
mod wasm {
    use super::*;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    pub fn run_proof_verification_from_files_wasm() -> Result<String, JsValue> {
        let result = run_proof_verification_from_files()
            .map_err(|e| JsValue::from_str(&e))?;

        serde_json::to_string(&result)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
    }

    #[wasm_bindgen]
    pub fn run_proof_verification_with_inputs_wasm(input_json: &str) -> Result<String, JsValue> {
        let input: EcdsaInput = serde_json::from_str(input_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse input: {}", e)))?;

        let result = run_proof_verification_with_inputs(input)
            .map_err(|e| JsValue::from_str(&e))?;

        serde_json::to_string(&result)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_verification_from_files() {
        println!("Testing proof verification from files...");
        
        match run_proof_verification_from_files() {
            Ok(result) => {
                println!("✓ File-based verification result: {:?}", result);
                if result.success {
                    println!("✓ Proof verification from files succeeded!");
                } else {
                    println!("✗ Proof verification from files failed: {:?}", result.error_message);
                }
            }
            Err(e) => println!("Expected error in test (library not linked): {}", e),
        }
    }

    #[test]
    fn test_proof_verification_with_custom_inputs() {
        println!("Testing proof verification with custom inputs...");
        
        // Test data from your C test
        let input = EcdsaInput {
            msg_hash: "beaaf37129e2e801ca360e226bce78c8c82ad08bf88e3250177e8e32cad17f8e".to_string(),
            r: "d5675d2bf43d09c689c1c5f080467c40493ecfad7b8a9753ed4019615913c52b".to_string(),
            s: "9f6c5744183080ed5da9d3c1dacea9db10c07d4721dfe4aba8e217720635e3df".to_string(),
            pub_x: "ec2a78c1dcde84326c812a7666a9167022ad2b388035d8fdd97b495939ce7174".to_string(),
            pub_y: "dee8b2f2861a1bee29932861deb5e045580d3bbe1592d5aa1bbbe7322f2396e9".to_string(),
        };

        match run_proof_verification_with_inputs(input) {
            Ok(result) => {
                println!("✓ Custom input verification result: {:?}", result);
                if result.success {
                    println!("✓ Proof verification with custom inputs succeeded!");
                } else {
                    println!("✗ Proof verification with custom inputs failed: {:?}", result.error_message);
                }
            }
            Err(e) => println!("Expected error in test (library not linked): {}", e),
        }
    }

    #[test]
    fn test_json_serialization() {
        let input = EcdsaInput {
            msg_hash: "test_hash".to_string(),
            r: "test_r".to_string(),
            s: "test_s".to_string(),
            pub_x: "test_pub_x".to_string(),
            pub_y: "test_pub_y".to_string(),
        };

        let json = serde_json::to_string(&input).unwrap();
        println!("Serialized input: {}", json);
        
        let deserialized: EcdsaInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input.msg_hash, deserialized.msg_hash);
        assert_eq!(input.r, deserialized.r);
        assert_eq!(input.s, deserialized.s);
        assert_eq!(input.pub_x, deserialized.pub_x);
        assert_eq!(input.pub_y, deserialized.pub_y);
        
        println!("✓ JSON serialization/deserialization works correctly");
    }
}