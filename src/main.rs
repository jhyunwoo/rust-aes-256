use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use clap::{Parser, Subcommand};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use std::fs;
use std::io::Write; // 사용하지 않는 Read를 제거했습니다.

// PBKDF2 설정값
const PBKDF2_ROUNDS: u32 = 100_000;
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// 파일을 암호화합니다.
    Encrypt {
        /// 암호화할 원본 파일 경로
        #[arg(short, long)]
        input: String,

        /// 암호화된 데이터를 저장할 파일 경로
        #[arg(short, long)]
        output: String,
    },
    /// 파일을 복호화합니다.
    Decrypt {
        /// 복호화할 암호화된 파일 경로
        #[arg(short, long)]
        input: String,

        /// 복호화된 데이터를 저장할 파일 경로
        #[arg(short, long)]
        output: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let password = rpassword::prompt_password("비밀번호를 입력하세요: ")?;

    match &cli.command {
        Commands::Encrypt { input, output } => {
            println!("암호화를 시작합니다...");
            encrypt_file(input, output, &password)?;
            println!("✅ 성공: '{}' 파일을 암호화하여 '{}'에 저장했습니다.", input, output);
        }
        Commands::Decrypt { input, output } => {
            println!("복호화를 시작합니다...");
            decrypt_file(input, output, &password)?;
            // --- 여기가 문제였습니다! 'o,utput'을 'output'으로 수정했습니다. ---
            println!("✅ 성공: '{}' 파일을 복호화하여 '{}'에 저장했습니다.", input, output);
        }
    }

    Ok(())
}

/// 비밀번호와 Salt로부터 암호화 키를 유도하는 함수
fn derive_key_from_password(password: &str, salt: &[u8]) -> Key<Aes256Gcm> {
    let mut key = [0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ROUNDS, &mut key);
    key.into()
}

/// 파일을 AES-256-GCM으로 암호화하는 함수
fn encrypt_file(input_path: &str, output_path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = fs::read(input_path)?;
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let key = derive_key_from_password(password, &salt);
    let cipher = Aes256Gcm::new(&key);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|e| format!("암호화 실패: {}", e))?;
    let mut output_file = fs::File::create(output_path)?;
    output_file.write_all(&salt)?;
    output_file.write_all(nonce.as_slice())?;
    output_file.write_all(&ciphertext)?;
    Ok(())
}

/// 파일을 AES-256-GCM으로 복호화하는 함수
fn decrypt_file(input_path: &str, output_path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let encrypted_data = fs::read(input_path)?;
    if encrypted_data.len() < SALT_SIZE + NONCE_SIZE {
        return Err("잘못된 파일 형식입니다. 파일이 너무 짧습니다.".into());
    }
    let (salt, rest) = encrypted_data.split_at(SALT_SIZE);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);
    let key = derive_key_from_password(password, salt);
    let cipher = Aes256Gcm::new(&key);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("복호화 실패 (비밀번호가 틀렸거나 파일이 손상되었을 수 있습니다): {}", e))?;
    fs::write(output_path, plaintext)?;
    Ok(())
}
