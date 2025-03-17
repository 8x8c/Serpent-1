use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::process::exit;

const BLOCK_SIZE: usize = 16;
const NUM_ROUNDS: usize = 32; // 32 rounds (dummy)
const NUM_ROUND_KEYS: usize = NUM_ROUNDS + 1;

// --- PKCS7 Padding ---

fn pkcs7_pad(data: &mut Vec<u8>) {
    let pad_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
    data.extend(vec![pad_len as u8; pad_len]);
}

fn pkcs7_unpad(data: &mut Vec<u8>) -> Result<(), String> {
    if data.is_empty() {
        return Err("Data is empty".to_string());
    }
    let pad_len = *data.last().unwrap() as usize;
    if pad_len == 0 || pad_len > BLOCK_SIZE {
        return Err("Invalid padding".to_string());
    }
    if data[data.len() - pad_len..].iter().any(|&b| b as usize != pad_len) {
        return Err("Invalid padding".to_string());
    }
    data.truncate(data.len() - pad_len);
    Ok(())
}

// --- Conversion Helpers: bytes <-> u32 words ---

fn bytes_to_words(block: &[u8]) -> [u32; 4] {
    let mut words = [0u32; 4];
    for i in 0..4 {
        words[i] = (block[i * 4] as u32)
            | ((block[i * 4 + 1] as u32) << 8)
            | ((block[i * 4 + 2] as u32) << 16)
            | ((block[i * 4 + 3] as u32) << 24);
    }
    words
}

fn words_to_bytes(words: &[u32; 4]) -> [u8; 16] {
    let mut block = [0u8; 16];
    for i in 0..4 {
        block[i * 4] = (words[i] & 0xff) as u8;
        block[i * 4 + 1] = ((words[i] >> 8) & 0xff) as u8;
        block[i * 4 + 2] = ((words[i] >> 16) & 0xff) as u8;
        block[i * 4 + 3] = ((words[i] >> 24) & 0xff) as u8;
    }
    block
}

// --- Dummy Key Schedule ---
// Uses a 16-byte key (converted to 4 u32 words) and produces NUM_ROUND_KEYS round keys.
fn serpent_key_schedule(key: &[u8]) -> Vec<[u32; 4]> {
    let mut round_keys = Vec::with_capacity(NUM_ROUND_KEYS);
    let base = bytes_to_words(key);
    for round in 0..NUM_ROUND_KEYS {
        let mut round_key = [0u32; 4];
        for i in 0..4 {
            // Dummy derivation: simply add the round number.
            round_key[i] = base[i].wrapping_add(round as u32);
        }
        round_keys.push(round_key);
    }
    round_keys
}

// --- Dummy Round Functions ---
//
// For each round we do:
// 1. Key mixing (XOR with round key)
// 2. S-box substitution (here: reverse bits, which is self-inverse)
// 3. Linear transformation (rotate left by 3 bits; inverse rotates right by 3)

fn dummy_sbox(x: u32) -> u32 {
    x.reverse_bits()
}

fn dummy_linear_transform(block: &mut [u32; 4]) {
    for i in 0..4 {
        block[i] = block[i].rotate_left(3);
    }
}

fn inverse_dummy_linear_transform(block: &mut [u32; 4]) {
    for i in 0..4 {
        block[i] = block[i].rotate_right(3);
    }
}

// --- Block Encryption ---
// Encrypts a single 16-byte block.
fn serpent_encrypt_block(block: &mut [u32; 4], round_keys: &[[u32; 4]]) {
    for round in 0..NUM_ROUNDS {
        // Key mixing
        for i in 0..4 {
            block[i] ^= round_keys[round][i];
        }
        // S-box substitution (self-inverse)
        for i in 0..4 {
            block[i] = dummy_sbox(block[i]);
        }
        // Linear transformation (skip in last round)
        if round < NUM_ROUNDS - 1 {
            dummy_linear_transform(block);
        }
    }
    // Final key mixing
    for i in 0..4 {
        block[i] ^= round_keys[NUM_ROUNDS][i];
    }
}

// --- Block Decryption ---
// Inverts the encryption steps in reverse order.
fn serpent_decrypt_block(block: &mut [u32; 4], round_keys: &[[u32; 4]]) {
    // Invert final key mixing
    for i in 0..4 {
        block[i] ^= round_keys[NUM_ROUNDS][i];
    }
    // Process rounds in reverse order
    for round in (0..NUM_ROUNDS).rev() {
        // Inverse linear transformation (if it was applied)
        if round < NUM_ROUNDS - 1 {
            inverse_dummy_linear_transform(block);
        }
        // Invert S-box (self-inverse)
        for i in 0..4 {
            block[i] = dummy_sbox(block[i]);
        }
        // Invert key mixing
        for i in 0..4 {
            block[i] ^= round_keys[round][i];
        }
    }
}

// --- Helper: Convert hex string to bytes ---
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string must have even length".to_string());
    }
    (0..hex.len() / 2)
        .map(|i| {
            let byte_str = &hex[i * 2..i * 2 + 2];
            u8::from_str_radix(byte_str, 16).map_err(|e| e.to_string())
        })
        .collect()
}

// --- Helper: Convert a 16-byte slice into [u32; 4] ---
fn bytes_to_array(bytes: &[u8]) -> [u32; 4] {
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes[0..16]);
    bytes_to_words(&arr)
}

//
// --- Main ---
//
// Usage: <enc|dec> <input file> <output file>
// Mode "enc" encrypts (with padding) and "dec" decrypts (removing padding).
//
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <enc|dec> <input file> <output file>", args[0]);
        exit(1);
    }

    let mode = &args[1];
    let input_filename = &args[2];
    let output_filename = &args[3];

    // Hard-coded key and IV (16 bytes each, expressed as 32 hex digits)
    let key_hex = "00112233445566778899aabbccddeeff";
    let iv_hex = "ffeeddccbbaa99887766554433221100";

    let key = hex_to_bytes(key_hex).expect("Invalid key hex");
    let iv = hex_to_bytes(iv_hex).expect("Invalid IV hex");

    // Generate round keys from the key.
    let round_keys = serpent_key_schedule(&key);

    // Read the input file.
    let mut file = File::open(input_filename).expect("Failed to open input file");
    let mut data = Vec::new();
    file.read_to_end(&mut data).expect("Failed to read file");

    let result_data = if mode == "enc" {
        // --- Encryption ---
        pkcs7_pad(&mut data);

        let mut ciphertext = Vec::new();
        // Start CBC with IV.
        let mut prev_block = bytes_to_array(&iv);

        for chunk in data.chunks(BLOCK_SIZE) {
            let mut block = bytes_to_array(chunk);
            // CBC XOR with previous ciphertext (or IV for first block)
            for i in 0..4 {
                block[i] ^= prev_block[i];
            }
            // Encrypt the block.
            serpent_encrypt_block(&mut block, &round_keys);
            ciphertext.extend_from_slice(&words_to_bytes(&block));
            // Update the previous block.
            prev_block = block;
        }
        ciphertext
    } else if mode == "dec" {
        // --- Decryption ---
        if data.len() % BLOCK_SIZE != 0 {
            eprintln!("Ciphertext length is not a multiple of block size");
            exit(1);
        }
        let mut plaintext = Vec::new();
        // For CBC, start with IV.
        let mut prev_block = bytes_to_array(&iv);
        for chunk in data.chunks(BLOCK_SIZE) {
            let mut block = bytes_to_array(chunk);
            // Decrypt the block.
            serpent_decrypt_block(&mut block, &round_keys);
            // CBC: XOR with previous ciphertext (or IV) to recover plaintext.
            for i in 0..4 {
                block[i] ^= prev_block[i];
            }
            plaintext.extend_from_slice(&words_to_bytes(&block));
            // Update previous block to current ciphertext block.
            prev_block = bytes_to_array(chunk);
        }
        // Remove PKCS7 padding.
        if let Err(e) = pkcs7_unpad(&mut plaintext) {
            eprintln!("Padding error: {}", e);
            exit(1);
        }
        plaintext
    } else {
        eprintln!("Invalid mode. Use 'enc' for encryption or 'dec' for decryption.");
        exit(1);
    };

    let mut out_file = File::create(output_filename).expect("Failed to create output file");
    out_file.write_all(&result_data).expect("Failed to write output file");

    println!("Operation '{}' complete.", mode);
}


