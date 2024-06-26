use mussh_protocol::{EncryptedTypedReader, EncryptedTypedWriter, TypedReader, TypedWriter};
use mussh_ui::{App, KeyReaction};
use rand::rngs::OsRng;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::{error::Error, io, net::TcpStream};

#[derive(Serialize, Deserialize, Debug)]
struct RSAKeys {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

fn main() -> Result<(), Box<dyn Error>> {
    // Etape 1: créer la structure
    let mut app = App::default();
    let mut rng = OsRng;

    let rsa_keys = rsa_keys_generation(&mut rng);

    let stream = TcpStream::connect("127.0.0.1:2222").expect("Failed to connect");
    let (mut encrypted_reader, mut encrypted_writer) = match init_session(&stream, &rsa_keys) {
        Some((encrypted_reader, encrypted_writer)) => (encrypted_reader, encrypted_writer),
        None => {
            eprintln!("Failed to update to encrypted streams");
            let var_name = Err(Box::new(std::fmt::Error));
            return var_name?;
        }
    };

    // Etape 2: on démarre la TUI
    app.start()?;

    loop {
        // Etape 3: on dessine l'application (à faire après chaque évènement lu,
        // y compris des changements de taille de la fenêtre !)
        app.draw()?;

        // Etape 4: on modifie l'état interne de l'application, en fonction des évènements
        // clavier / système. Ici, l'interface est très simple: suite à un évènement, soit:
        // - l'évènement est géré en interne de App, il n'y a rien à faire
        // - soit l'utilisateur veut quitter l'application, il faut interrompre la boucle et retourner
        // - soit l'utilisateur souhaite envoyer une commande verse le serveur

        // TODO par ailleurs, il faudra afficher (via push_message) les données reçues depuis le serveur

        if let Ok(e) = crossterm::event::read() {
            match app.react_to_event(e) {
                Some(KeyReaction::Quit) => {
                    break;
                }
                Some(KeyReaction::UserInput(s)) => {
                    // TODO pour l'instant, le message à envoyer est simplement affiché localement
                    // Il faudra l'envoyer au serveur mini-ssh;
                    // Envoi la commande au serveur

                    //let data = encrypted_reader.recv().expect("Failed to get data");
                    //app.push_message(data);

                    encrypted_writer.send(&s).expect("Failed to send data");
                    app.push_message(s);

                    app.draw()?;

                    let recieved_data = encrypted_reader.recv().expect("Failed to get server data");
                    for line in recieved_data {
                        app.push_message(line);
                    }
                }
                None => {} // Rien à faire, géré en interne
            }
        }
    }
    Ok(())
}

fn rsa_keys_generation(rng: &mut OsRng) -> RSAKeys {
    println!("Generating RSA keys");
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(rng, bits).expect("failed to generate a key");
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
    rsa_typed_writer
        .send(&rsa_keys.public_key)
        .expect("Failed to send client public key");

    let server_public_key = rsa_typed_reader
        .recv()
        .expect("Failed to get server public key");
    server_public_key
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
    server_public_key: &RsaPublicKey,
    typed_writer: &mut TypedWriter<&TcpStream, Vec<u8>>,
    data: &[u8],
) {
    let enc_data = server_public_key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, data)
        .expect("Failed to encrypt data");

    typed_writer.send(&enc_data).expect("Failed to send data");
}

fn get_user_password() -> String {
    let password = rpassword::prompt_password("Password: ").expect("Unable to read the password");
    password
}

fn init_session<'a>(
    stream: &'a TcpStream,
    rsa_keys: &'a RSAKeys,
) -> Option<(
    EncryptedTypedReader<&'a TcpStream, Vec<String>>,
    EncryptedTypedWriter<&'a TcpStream, String>,
)> {
    let mut rsa_typed_reader = TypedReader::<_, RsaPublicKey>::new(stream);
    let mut rsa_typed_writer = TypedWriter::<_, RsaPublicKey>::new(stream);

    let server_public_key =
        exchange_public_keys(&mut rsa_typed_reader, &mut rsa_typed_writer, &rsa_keys);

    let mut typed_reader = TypedReader::<_, Vec<u8>>::new(stream);
    let mut typed_writer = TypedWriter::<_, Vec<u8>>::new(stream);

    let username_msg = recv_and_decrypt(&rsa_keys, &mut typed_reader);
    println!(
        "{}",
        String::from_utf8(username_msg).expect("Failed to convert vector to string")
    );

    // Read user input
    let mut username = String::new();
    let stdin = io::stdin();
    stdin
        .read_line(&mut username)
        .expect("Failed to read username");

    encrypt_and_send(&server_public_key, &mut typed_writer, &username.as_bytes());

    let password_msg = recv_and_decrypt(&rsa_keys, &mut typed_reader);
    println!(
        "{}",
        String::from_utf8(password_msg).expect("Failed to convert vector to string")
    );

    let password = get_user_password();

    encrypt_and_send(&server_public_key, &mut typed_writer, &password.as_bytes());
    let aes_key = recv_and_decrypt(rsa_keys, &mut typed_reader);
    if !aes_key.is_empty() {
        let encrypted_reader =
            EncryptedTypedReader::<_, Vec<String>>::try_new(stream, aes_key.as_slice())
                .expect("Failed to upgrade to encrypted reader");
        let encrypted_writer =
            EncryptedTypedWriter::<_, String>::try_new(stream, aes_key.as_slice())
                .expect("Failed to upgrade to encrypted writer");
        Some((encrypted_reader, encrypted_writer))
    } else {
        None
    }
}
