use std::fs;
use std::io::{self, Write};
use std::path::Path;
use anyhow::{Result, anyhow};
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;
use rand::RngCore;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};

const EXCLUDE_FILES: &[&str] = &["main.rs", "encrypt.exe", "decrypt.exe"];

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, 1_000_000, &mut key);
    key
}

fn encrypt_files_in_dir(password: &str) -> Result<()> {
    for entry in fs::read_dir(".")? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            let filename = path.file_name().unwrap().to_string_lossy();
            if EXCLUDE_FILES.contains(&filename.as_ref()) {
                continue;
            }

            println!("Encryptingg: {}", filename);

            let plaintext = fs::read(&path)
                .map_err(|e| anyhow!("えらー；； {}: {}", filename, e))?;
            let mut salt = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut salt);
            let mut iv = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut iv);

            let key_bytes = derive_key(password, &salt);
            let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
            let cipher = Aes256Gcm::new(key);
            let nonce = Nonce::from_slice(&iv);

            let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
                .map_err(|e| anyhow!("ERA------------ {}: {}", filename, e))?;
            let mut encrypted_data = Vec::with_capacity(salt.len() + iv.len() + ciphertext.len());
            encrypted_data.extend_from_slice(&salt);
            encrypted_data.extend_from_slice(&iv);
            encrypted_data.extend_from_slice(&ciphertext);

            fs::write(&path, &encrypted_data)
                .map_err(|e| anyhow!("ERA------{}: {}", filename, e))?;
        }
    }
    Ok(())
}

fn decrypt_files_in_dir(password: &str) -> Result<usize> {
    let mut success_count = 0;

    for entry in fs::read_dir(".")? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            let filename = path.file_name().unwrap().to_string_lossy();

            if EXCLUDE_FILES.contains(&filename.as_ref()) {
                continue;
            }

            let data = fs::read(&path)
                .map_err(|e| anyhow!("era---- {}: {}", filename, e))?;

            if data.len() < 28 {
                eprintln!("era----  {}", filename);
                continue;
            }

            let salt = &data[0..16];
            let iv = &data[16..28];
            let ciphertext = &data[28..];

            let key_bytes = derive_key(password, salt);
            let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
            let cipher = Aes256Gcm::new(key);
            let nonce = Nonce::from_slice(iv);

            match cipher.decrypt(nonce, ciphertext) {
                Ok(plaintext) => {
                    fs::write(&path, &plaintext)
                        .map_err(|e| anyhow!("era----  {}: {}", filename, e))?;
                    println!("Decrypted: {}", filename);
                    success_count += 1;
                }
                Err(_) => {
                    eprintln!("era----  {}", filename);
                    continue;
                }
            }
        }
    }

    Ok(success_count)
}

fn prompt_input(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?; 
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string()) 
}

fn main() -> Result<()> {
    println!("モードを選択してください。\n1. 暗号化\n2. 復号化");

    let mode_str = prompt_input("モード番号を入力: ")?;
    let mode: u8 = mode_str.parse()
        .map_err(|_| anyhow!("無効な入力です。1か2を入力してください。"))?;

    if mode != 1 && mode != 2 {
        println!("存在しないモードです。");
        return Ok(());
    }

    println!("このファイルを対象のディレクトリに置いて実行してください。");

    let confirm = prompt_input("続行しますか？ (y/n): ")?;
    if confirm.to_lowercase() != "y" {
        println!("処理を中止しました。");
        return Ok(());
    }

    let password = prompt_input("パスワードを入力してください: ")?;

    if mode == 1 {
        println!("暗号化を開始します...");
        encrypt_files_in_dir(&password)?;
        println!("暗号化が完了しました。");
    } else {
        println!("復号化を開始します...");
        let count = decrypt_files_in_dir(&password)?;
        println!("復号化が完了しました。復号したファイル数: {}", count);
    }

    Ok(())
}