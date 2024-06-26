use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use clap::{Args, Parser, Subcommand};
use mussh_protocol::*;
use rand::rngs::OsRng;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::{
    env::{self},
    fs::{File, OpenOptions},
    io::{Read, Write},
    iter::once,
    net::{TcpListener, TcpStream},
};

#[derive(Debug, Subcommand)]
pub enum CommandClap {
    Listen(ListenArgs),
    AddUser(AddUserArgs),
}

#[derive(Debug, Args)]
pub struct AddUserArgs {
    #[arg(short, long)]
    username: String,
}

#[derive(Debug, Args)]
pub struct ListenArgs {
    #[arg(short, long)]
    port: u16,
}
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct ArgsCli {
    /// Port of the server
    #[command(subcommand)]
    command: CommandClap,
}

#[derive(Serialize, Deserialize, Debug)]
struct Credentials {
    username: String,
    hash: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct RSAKeys {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

pub const PATH: &str = "server/src/database.json";

fn main() {
    let args = ArgsCli::parse();

    match args.command {
        CommandClap::Listen(port) => {
            let mut addr = String::new();
            addr.push_str("127.0.0.1:");
            addr.push_str(&port.port.to_string());
            let socket = TcpListener::bind(addr).expect("Failed to bind socket");

            let rsa_keys = rsa_keys_generation();

            for stream in socket.incoming() {
                let stream = stream.expect("Failed to get stream from listener");
                let (mut encrypted_reader, mut encrypted_writer) =
                    match init_session(&stream, &rsa_keys) {
                        Some((encrypted_reader, encrypted_writer)) => {
                            (encrypted_reader, encrypted_writer)
                        }
                        None => {
                            eprintln!("Failed to update to encrypted streams");
                            return;
                        }
                    };

                let mut input = encrypted_reader
                    .recv()
                    .expect("Failed to get client command");

                while !input.is_empty() {
                    println!("Command : {}", input);
                    let mut cmd_iter = input.split_whitespace();
                    let cmd = cmd_iter.next().expect("Failed to parse command");
                    let args_iter = once(cmd).chain(cmd_iter);

                    let data_to_send = if cmd == "cd" {
                        let dir = args_iter
                            .skip(1)
                            .next()
                            .expect("Expected a directory argument for cd command");

                        let result = match env::set_current_dir(dir) {
                            Ok(_) => {
                                let mut vec = Vec::new();
                                vec.push(String::new());
                                vec
                            }
                            Err(e) => {
                                let mut vec = Vec::new();
                                vec.push(e.to_string());
                                vec
                            }
                        };
                        result
                    } else {
                        let mut command = Command::new(cmd);
                        for arg in args_iter.skip(1) {
                            command.arg(arg);
                        }
                        let command_output = match command.output() {
                            Ok(output) => output.stdout,
                            Err(_) => Vec::new(),
                        };

                        let command_output = if command_output.is_empty() {
                            let mut vec = Vec::new();
                            vec.push("Failed to execute the given command".to_string());
                            vec
                        } else {
                            let command_output_str = String::from_utf8_lossy(&command_output);
                            let command_output_lines: Vec<String> = command_output_str
                                .split('\n')
                                .map(|s| s.to_string())
                                .collect();
                            command_output_lines
                        };
                        command_output
                    };

                    encrypted_writer
                        .send(&data_to_send)
                        .expect("Failed to send command output");

                    input = encrypted_reader
                        .recv()
                        .expect("Failed to get client command 2");
                }
            }
        }
        CommandClap::AddUser(AddUserArgs { username }) => {
            let password = get_user_password();
            add_user_in_db(&username, &password);
        }
    }
}

fn get_user_password() -> String {
    let password = rpassword::prompt_password("Password: ").expect("Unable to read the password");
    password
}

fn hash_password(user_password: &str) -> String {
    //let salt: [u8; 32] = rand::random();
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(user_password.as_bytes(), &salt)
        .expect("Unable to hash the given password");
    return hash.to_string();
}

fn write_credentials_in_db(database: &mut File, username: &String, password_to_write: &String) {
    let hash = hash_password(&password_to_write);

    let mut current_content = Vec::new();
    database
        .read_to_end(&mut current_content)
        .expect("Failed to read the database");

    let mut current_content: Vec<Credentials> = match serde_json::from_slice(&current_content) {
        Ok(v) => v,
        Err(_) => Vec::new(),
    };

    let credentials: Credentials = Credentials {
        username: username.to_owned(),
        hash: hash.to_owned(),
    };

    current_content.push(credentials);

    let current_content =
        serde_json::to_string(&current_content).expect("Failed to convert vector to string");

    database
        .write_all(&current_content.as_bytes())
        .expect("failed to write");
}

fn add_user_in_db(username: &String, user_password: &String) {
    let mut database_io = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(PATH)
        .expect("Unable to open database.txt");

    // Write hash into db
    write_credentials_in_db(&mut database_io, username, user_password);
}

fn check_user_password(username: &String, user_password: &String) -> bool {
    // Open the file in read-only mode
    let mut database_io = OpenOptions::new()
        .read(true)
        .open(PATH)
        .expect("Unable to open database.txt");

    // Read the content of the db and put it into a vector
    let mut current_content = Vec::new();
    database_io
        .read_to_end(&mut current_content)
        .expect("Failed to read the database");

    // Try to convert JSON to vector
    let current_content: Vec<Credentials> = match serde_json::from_slice(&current_content) {
        Ok(v) => v,
        Err(_) => Vec::new(),
    };

    // Look for a user with the name given into the parameters
    let current_creds = match current_content.iter().find(|c| c.username == *username) {
        Some(user_credentials) => user_credentials,
        None => {
            println!("No user found with this username");
            return false;
        }
    };
    // Convert the string to hash

    let parsed_hash =
        PasswordHash::new(&current_creds.hash).expect("Failed to convert the string to a hash");

    // Compare the hashed input with the contents of the file
    if Argon2::default()
        .verify_password(user_password.as_bytes(), &parsed_hash)
        .is_ok()
    {
        return true;
    } else {
        return false;
    }
}

fn rsa_keys_generation() -> RSAKeys {
    println!("Generating RSA keys");
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut OsRng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);
    println!("Keys generated");
    RSAKeys {
        private_key: priv_key,
        public_key: pub_key,
    }
}

fn exchange_public_keys(
    rsa_typed_reader: &mut TypedReader<&TcpStream, RsaPublicKey>,
    rsa_typed_writer: &mut TypedWriter<&TcpStream, RsaPublicKey>,
    rsa_keys: &RSAKeys,
) -> RsaPublicKey {
    let client_public_key = rsa_typed_reader
        .recv()
        .expect("Failed to get client public key");

    rsa_typed_writer
        .send(&rsa_keys.public_key)
        .expect("Failed to send server public key");

    client_public_key
}

/**
 * This function run recv() on the reader and returns the decrypted data
 */
fn recv_and_decrypt(
    rsa_keys: &RSAKeys,
    typed_reader: &mut TypedReader<&TcpStream, Vec<u8>>,
) -> Vec<u8> {
    let enc_data = typed_reader.recv().expect("Failed to get data");
    let dec_data = rsa_keys
        .private_key
        .decrypt(Pkcs1v15Encrypt, &enc_data)
        .expect("Failed to decrypt data");
    dec_data
}

fn encrypt_and_send(
    client_public_key: &RsaPublicKey,
    typed_writer: &mut TypedWriter<&TcpStream, Vec<u8>>,
    data: &[u8],
) {
    let enc_data = client_public_key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, data)
        .expect("Failed to encrypt data");

    typed_writer.send(&enc_data).expect("Failed to send data");
}

/**
 * This function does the init of the exchange. The following jobs are done :
 *  - RSA key generation
 *  - RSA public key exchange with the client
 *  - Asks for the username and gets it
 *  - Asks for the password and gets it
 *  - Check for the user credentials
 */
fn init_session<'a>(
    stream: &'a TcpStream,
    rsa_keys: &'a RSAKeys,
) -> Option<(
    EncryptedTypedReader<&'a TcpStream, String>,
    EncryptedTypedWriter<&'a TcpStream, Vec<String>>,
)> {
    let mut rsa_typed_reader = TypedReader::<_, RsaPublicKey>::new(stream);
    let mut rsa_typed_writer = TypedWriter::<_, RsaPublicKey>::new(stream);

    let client_public_key =
        exchange_public_keys(&mut rsa_typed_reader, &mut rsa_typed_writer, &rsa_keys);

    let mut typed_reader = TypedReader::<_, Vec<u8>>::new(stream);
    let mut typed_writer = TypedWriter::<_, Vec<u8>>::new(stream);

    encrypt_and_send(
        &client_public_key,
        &mut typed_writer,
        "What is your username ?".as_bytes(),
    );

    let username = recv_and_decrypt(&rsa_keys, &mut typed_reader);
    let username = String::from(
        std::str::from_utf8(username.as_ref()).expect("Failed to converted vector to str"),
    )
    .trim()
    .to_string();

    encrypt_and_send(
        &client_public_key,
        &mut typed_writer,
        "What is your password ?".as_bytes(),
    );

    let password = recv_and_decrypt(&rsa_keys, &mut typed_reader);
    let password = String::from(
        std::str::from_utf8(password.as_ref()).expect("Failed to converted vector to str"),
    );

    if check_user_password(&username, &password) {
        let aes_key = rand::random::<[u8; 32]>();
        encrypt_and_send(&client_public_key, &mut typed_writer, &aes_key);
        let encrypted_reader = EncryptedTypedReader::<_, String>::try_new(stream, &aes_key)
            .expect("Failed to upgrade to encrypted reader");
        let encrypted_writer = EncryptedTypedWriter::<_, Vec<String>>::try_new(stream, &aes_key)
            .expect("Failed to upgrade to encrypted writer");
        Some((encrypted_reader, encrypted_writer))
    } else {
        encrypt_and_send(&client_public_key, &mut typed_writer, &[]); // Send an empty key on failure
        None
    }
}
