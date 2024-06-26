use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit};
use serde::de::DeserializeOwned;
use std::fmt::Debug;
use std::io::{ErrorKind, Read, Write};

use tracing::info;

/// Canal de communication côté réception, typé et **synchrone**. Permet de recevoir un type quelconque via
/// une socquette TCP par exemple, dès lors que le type à envoyer implémente [`serde::Serialize`] et [`serde::Deserialize`].
/// La socquette doit par ailleurs implémenter [`Read`].
///
/// # Exemple
///
/// ```no_run
/// use std::net::TcpStream;
///
/// let stream = TcpStream::connect("serveur:port").unwrap();
/// let mut typed_reader = TypedReader::<_, String>::new(stream);
/// let response: String = typed_reader.recv().unwrap();
/// ```
///
/// Ceci recevra une requête du serveur, qui aura été envoyée par le biais d'un [`TypedWriter`] pour le même type.

#[derive(Debug)]
pub struct TypedReader<Stream, T>
where
    Stream: Read,
{
    pub stream: Stream,
    _t: std::marker::PhantomData<*const T>,
}

unsafe impl<Stream, T> Send for TypedReader<Stream, T> where Stream: Send + Read {}

impl<Stream, T> TypedReader<Stream, T>
where
    Stream: Read,
{
    /// Créé un nouveau TypedReader
    pub fn new(stream: Stream) -> Self {
        Self {
            stream,
            _t: std::marker::PhantomData,
        }
    }

    /// Retourne le canal sous-jacent
    pub fn into_inner(self) -> Stream {
        self.stream
    }
}

impl<Stream, T> TypedReader<Stream, T>
where
    Stream: Read + std::fmt::Debug,
    T: DeserializeOwned + std::fmt::Debug,
{
    /// Reçoit un type via le canal de réception. Il doit avoir été envoyé via
    /// la fonction [`TypedWriter::send`].
    ///
    /// Renvoie une erreur en cas d'erreur du canal sous-jacent, et
    /// `None` en cas d'erreur de déserialisation.
    #[tracing::instrument(level = "debug")]
    pub fn recv(&mut self) -> std::io::Result<T> {
        // Read the size, from u32
        info!("Receiving data");
        let mut size = [0; 4];
        self.stream.read_exact(&mut size)?;
        let size = u32::from_be_bytes(size);
        // Prepare a buffer
        let mut buf = vec![0; size as usize];
        self.stream.read_exact(&mut buf)?;

        info!("Data received");
        // Deserialize the value, discard the potential deserializing error
        bincode::deserialize(&buf).map_err(|_| {
            std::io::Error::new(ErrorKind::InvalidInput, "Invalid data for deserialization")
        })
    }
}
/// Canal de communication côté émission, typé et **synchrone**. Permet d'envoyer un type quelconque via
/// une socquette TCP par exemple, dès lors que le type à envoyer implémente [`serde::Serialize`] et [`serde::Deserialize`].
/// La socquette doit par ailleurs implémenter [`Write`].
///
/// # Exemple
///
/// ```no_run
/// use std::net::TcpStream;
///
/// let stream = TcpStream::connect("serveur:port").unwrap();
/// let mut typed_writer = TypedWriter::<_, String>::new(stream);
/// typed_writer.send("toto".to_string()).unwrap();
/// ```
///
/// Ceci enverra une requête au serveur, qui devra être reçue via un [`TypedReader`] pour le même type.
#[derive(Debug)]
pub struct TypedWriter<Stream, T>
where
    Stream: Write,
{
    pub stream: Stream,
    _t: std::marker::PhantomData<*const T>,
}

unsafe impl<Stream, T> Send for TypedWriter<Stream, T> where Stream: Send + Write {}

impl<Stream, T> TypedWriter<Stream, T>
where
    Stream: Write,
{
    /// Créé un nouveau TypedReader
    pub fn new(stream: Stream) -> Self {
        Self {
            stream,
            _t: std::marker::PhantomData,
        }
    }

    /// Retourne le canal sous-jacent
    pub fn into_inner(self) -> Stream {
        self.stream
    }
}

impl<Stream, T> TypedWriter<Stream, T>
where
    Stream: Write + std::fmt::Debug,
    T: serde::Serialize + std::fmt::Debug,
{
    /// Envoie un type via le canal sélectionné. Une erreur est envoyée en cas
    /// d'erreur du canal sous-jacent.
    #[tracing::instrument(level = "info")]
    pub fn send(&mut self, value: &T) -> std::io::Result<()> {
        let data: Vec<u8> = bincode::serialize(value).unwrap();
        // Send the size, as u32
        self.stream.write_all(&(data.len() as u32).to_be_bytes())?;
        self.stream.write_all(&data)
    }
}

/// Canal de communication  chiffré côté émission, typé et **synchrone**. Permet d'envoyer un type quelconque via
/// une socquette TCP par exemple, dès lors que le type à envoyer implémente [`serde::Serialize`] et [`serde::Deserialize`].
/// La socquette doit par ailleurs implémenter [`Write`].
///
/// # Exemple
///
/// ```no_run
/// use std::net::TcpStream;
/// use rand::prelude::*;
/// let stream = TcpStream::connect("serveur:port").unwrap();
/// let mut typed_reader = TypedReader::<_, String>::new(stream);
/// let response: String = typed_reader.recv().unwrap();
///
/// // Mise à jour vers canal sécurisé
/// let mut rng = rand::thread_rng();
/// let shared_key: [u8;32] = rng.gen();
///
/// // La clé doit être partagée entre client et serveur  
/// let encrypted_reader = EncryptedTypedWriter::try_new(typed_reader.into_inner(), shared_key.as_slice()).unwrap(),
///
/// let msg: String = encrypted_reader.recv().unwrap();
/// ```
///
/// Ceci reçoit une requête (du client ou serveur), qui devra avoir été envoyée via un [`EncryptedTypedWriter`] pour le même type
/// et la même clé.
#[derive(Debug)]
pub struct EncryptedTypedReader<Stream, T>
where
    Stream: Read,
{
    pub stream: Stream,
    key: Key<Aes256Gcm>,
    _t: std::marker::PhantomData<*const T>,
}

unsafe impl<Stream, T> Send for EncryptedTypedReader<Stream, T> where Stream: Send + Read {}

impl<Stream, T> EncryptedTypedReader<Stream, T>
where
    Stream: Read,
{
    /// Créé un nouveau TypedReader
    pub fn try_new(stream: Stream, key: &[u8]) -> Option<Self> {
        if key.len() != 32 {
            return None;
        }
        let key = *(Key::<Aes256Gcm>::from_slice(key));
        Some(Self {
            stream,
            key,
            _t: std::marker::PhantomData,
        })
    }

    /// Retourne le canal sous-jacent
    pub fn into_inner(self) -> Stream {
        self.stream
    }
}

impl<Stream, T> EncryptedTypedReader<Stream, T>
where
    Stream: Read + std::fmt::Debug,
    T: DeserializeOwned + std::fmt::Debug,
{
    /// Reçoit un type via le canal de réception en le déchiffrant. Il doit avoir été envoyé via
    /// la fonction [`EncryptedTypedWriter::send`].
    ///
    /// Renvoie une erreur en cas d'erreur du canal sous-jacent
    #[tracing::instrument(level = "debug")]
    pub fn recv(&mut self) -> std::io::Result<T> {
        // Read the size, from u32
        info!("Receiving data");
        let mut size = [0; 4];
        self.stream.read_exact(&mut size)?;
        let size = u32::from_be_bytes(size);

        // Read the IV
        let mut nonce = [0; 12];
        self.stream.read_exact(&mut nonce)?;
        // Prepare a buffer
        let mut buf = vec![0; size as usize];
        self.stream.read_exact(&mut buf)?;

        let aes = Aes256Gcm::new(&self.key);
        let decrypted = aes.decrypt((&nonce).into(), &*buf).map_err(|_| {
            std::io::Error::new(ErrorKind::InvalidInput, "Decryption error on data")
        })?;

        info!("Data received");
        // Deserialize the value, discard the potential deserializing error
        bincode::deserialize::<T>(&decrypted).map_err(|_| {
            std::io::Error::new(ErrorKind::InvalidInput, "Invalid data for deserialization")
        })
    }
}
/// Canal de communication côté émission, typé et **synchrone**. Permet d'envoyer un type quelconque via
/// une socquette TCP par exemple, dès lors que le type à envoyer implémente [`serde::Serialize`] et [`serde::Deserialize`].
/// La socquette doit par ailleurs implémenter [`Write`].
///
/// # Exemple
///
/// ```no_run
/// use std::net::TcpStream;
/// use mini_irc_protocol::Request;
/// use mini_irc_protocol::TypedWriter;
///
/// let stream = TcpStream::connect("serveur:port").unwrap();
/// let mut typed_writer = TypedWriter::<_, String>::new(stream);
/// typed_writer.send("toto".to_string()).unwrap();
///
/// // Mise à jour vers canal sécurisé
/// let mut rng = rand::thread_rng();
/// let shared_key: [u8;32] = rng.gen();
///
/// // La clé doit être partagée entre client et serveur  
/// let encrypted_reader = EncryptedTypedWriter::try_new(typed_reader.into_inner(), shared_key.as_slice()).unwrap(),
///
/// let mut typed_writer = EncryptedTypedWriter::<_, String>::new(stream);
/// typed_writer.send("foobar".to_string()).unwrap();
/// ```
///
/// Ceci enverra une requête au serveur ou au client , qui devra être reçue via un
/// un [`EncryptedTypedReader`] pour le même type et la même clé.
#[derive(Debug)]
pub struct EncryptedTypedWriter<Stream, T>
where
    Stream: Write,
{
    pub stream: Stream,
    key: Key<Aes256Gcm>,
    _t: std::marker::PhantomData<*const T>,
}

unsafe impl<Stream, T> Send for EncryptedTypedWriter<Stream, T> where Stream: Send + Write {}

impl<Stream, T> EncryptedTypedWriter<Stream, T>
where
    Stream: Write,
{
    /// Créé un nouveau TypedReader
    pub fn try_new(stream: Stream, key: &[u8]) -> Option<Self> {
        if key.len() != 32 {
            return None;
        }
        let key = *(aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(key));
        Some(Self {
            stream,
            key,
            _t: std::marker::PhantomData,
        })
    }

    /// Retourne le canal sous-jacent
    pub fn into_inner(self) -> Stream {
        self.stream
    }
}

impl<Stream, T> EncryptedTypedWriter<Stream, T>
where
    Stream: Write + std::fmt::Debug,
    T: serde::Serialize + std::fmt::Debug,
{
    /// Envoie un type via le canal sélectionné. Une erreur est envoyée en cas
    /// d'erreur du canal sous-jacent.
    #[tracing::instrument(level = "info")]
    pub fn send(&mut self, value: &T) -> std::io::Result<()> {
        let data: Vec<u8> = bincode::serialize(value).unwrap();

        let aes = Aes256Gcm::new(&self.key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let encrypted = aes
            .encrypt(&nonce, &*data)
            .expect("AES-GCM encryption should never fail");
        // Send the size, as u32
        self.stream
            .write_all(&(encrypted.len() as u32).to_be_bytes())?;
        self.stream.write_all(&nonce)?;
        self.stream.write_all(&encrypted)
    }
}
