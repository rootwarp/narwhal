// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use base64ct::{Base64, Encoding};
use rust_secp256k1::{self, Message, Secp256k1};
use serde::{de, Deserialize, Serialize};
use signature::{Signature, Signer, Verifier};
use std::fmt::{Display, self};
use crate::traits::{
    Authenticator, EncodeDecodeBase64, KeyPair, SigningKey, ToFromBytes, VerifyingKey,
};
use serde_bytes::ByteBuf as SerdeByteBuf;
use serde::de::Error as SerdeError;
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EcdsaPublicKey(pub rust_secp256k1::PublicKey);


#[derive(Debug)]
pub struct EcdsaPrivateKey(pub rust_secp256k1::SecretKey);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSignature(pub rust_secp256k1::ecdsa::Signature);

impl VerifyingKey for EcdsaPublicKey {
    type PrivKey = EcdsaPrivateKey;

    type Sig = EcdsaSignature;
}

impl Verifier<EcdsaSignature> for EcdsaPublicKey {
    fn verify(&self, msg: &[u8], signature: &EcdsaSignature) -> Result<(), signature::Error> {
        let s = rust_secp256k1::Secp256k1::new();
        let message = Message::from_slice(msg).expect("32 bytes");
        s.verify_ecdsa(&message, &signature.0, &self.0).map_err(|_e| signature::Error::new())
    }
}

impl ToFromBytes for EcdsaPublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        let pubkey = rust_secp256k1::PublicKey::from_slice(bytes).map_err(|_e| signature::Error::new())?;
        Ok(EcdsaPublicKey(pubkey))
    }
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsRef<[u8]> for EcdsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0.serialize()
    }
}

impl Default for EcdsaPublicKey {
    fn default() -> Self {
        EcdsaPublicKey::from_bytes(&[0u8; 32]).unwrap()
    }
}

impl Display for EcdsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

// impl PartialOrd for EcdsaPublicKey {
//     fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
//         self.0.as_bytes().partial_cmp(other.0.as_bytes())
//     }
// }

// impl Ord for EcdsaPublicKey {
//     fn cmp(&self, other: &Self) -> std::cmp::Ordering {
//         self.0.as_bytes().cmp(other.0.as_bytes())
//     }
// }

// There is a strong requirement for this specific impl. in Fab benchmarks
impl Serialize for EcdsaPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let str = self.encode_base64();
        serializer.serialize_newtype_struct("EcdsaPublicKey", &str)
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl<'de> Deserialize<'de> for EcdsaPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl SigningKey for EcdsaPrivateKey {
    type PubKey = EcdsaPublicKey;

    type Sig = EcdsaSignature;
}

impl ToFromBytes for EcdsaPrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        rust_secp256k1::SecretKey::from_slice(bytes).map(EcdsaPrivateKey).map_err(|_e| signature::Error::new())
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl Serialize for EcdsaPrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let str = self.encode_base64();
        serializer.serialize_newtype_struct("Ed25519PublicKey", &str)
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl<'de> Deserialize<'de> for EcdsaPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl Serialize for EcdsaSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_ref().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EcdsaSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(SerdeError::custom)
    }

    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Default implementation just delegates to `deserialize` impl.
        *place = Deserialize::deserialize(deserializer)?;
        Ok(())
    }
}
impl Authenticator for EcdsaSignature {
    type PubKey = EcdsaPublicKey;

    type PrivKey = EcdsaPrivateKey;
}

impl AsRef<[u8]> for EcdsaPrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Signature for EcdsaSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        rust_secp256k1::ecdsa::Signature::from_der(bytes).map(EcdsaSignature).map_err(|_e| signature::Error::new())
    }
}

impl AsRef<[u8]> for EcdsaSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0.serialize_der()
    }
}

impl Display for EcdsaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode_string(self.as_ref()))
    }
}

// see [#34](https://github.com/MystenLabs/narwhal/issues/34)
impl Default for EcdsaSignature {
    fn default() -> Self {
        let sig = rust_secp256k1::ecdsa::Signature::from_der(&[0u8; 64]).unwrap();
        EcdsaSignature(sig)
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")] // necessary so as not to deser under a != type
pub struct EcdsaKeyPair {
    pub name: EcdsaPublicKey,
    pub secret: EcdsaPrivateKey,
}

impl KeyPair for EcdsaKeyPair {
    type PubKey = EcdsaPublicKey;

    type PrivKey = EcdsaPrivateKey;

    fn public(&'_ self) -> &'_ Self::PubKey {
        &self.name
    }

    fn private(self) -> Self::PrivKey {
        self.secret
    }

    fn generate<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Self {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(rng);
        EcdsaKeyPair {
            name: EcdsaPublicKey(public_key),
            secret: EcdsaPrivateKey(secret_key),
        }
    }
}

impl From<rust_secp256k1::KeyPair> for EcdsaKeyPair {
    fn from(kp: rust_secp256k1::KeyPair) -> Self {
        EcdsaKeyPair {
            name: EcdsaPublicKey(kp.public_key()),
            secret: EcdsaPrivateKey(kp.secret_key()),
        }
    }
}

impl Signer<EcdsaSignature> for EcdsaKeyPair {
    fn try_sign(&self, msg: &[u8]) -> Result<EcdsaSignature, signature::Error> {
        let privkey: &rust_secp256k1::SecretKey = &self.secret.0;
        let pubkey: &rust_secp256k1::PublicKey = &self.name.0;
        let message = Message::from_slice(msg).expect("32 bytes");
        let secp = rust_secp256k1::Secp256k1::new();
        Ok(EcdsaSignature(secp.sign_ecdsa(&message, privkey)))
    }
}
