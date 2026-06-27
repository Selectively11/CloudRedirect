#pragma once
// Minimal OpenPGP subset for Proton Drive node key operations.
//
// Implements:
//   - RSA-2048 key pair generation
//   - OpenPGP Secret Key Packet (tag 5) encoding + armoring
//   - Public-Key Encrypted Session Key (PKESK, tag 1) + SEIPD (tag 18) message encoding
//   - AES-256-GCM content encryption / decryption
//   - HMAC-SHA256 name hashing
//   - ASCII armor (PGP headers + base64 + CRC24)
//
// All platform crypto is handled via BCrypt (Windows) or OpenSSL (Linux).

#include <cstdint>
#include <string>
#include <vector>

namespace ProtonPGP {

// Opaque RSA key handle.
struct RsaKeyPair {
    std::vector<uint8_t> n, e, d, p, q, dp, dq, qi; // big-endian MPI bytes
};

// X25519 address key (Proton's "new" ECC key format). Only used for decrypting
// the Drive share passphrase during GetRootFolderNode() -- all node keys in the
// share's key chain remain RSA-2048 regardless of the address key's type.
struct EccKeyPair {
    std::vector<uint8_t> x25519Priv;  // 32 bytes, raw little-endian scalar
    std::vector<uint8_t> x25519Pub;   // 32 bytes, raw little-endian point
    std::vector<uint8_t> fingerprint; // 20 bytes, SHA-1 fingerprint of the subkey's public packet
};

// Generate a fresh RSA-2048 key pair. Returns false on failure.
bool GenerateRsaKeyPair(RsaKeyPair& out);

// Serialise the key pair as an OpenPGP Secret Key Packet (new format, tag 5)
// with the given passphrase used for S2K protection (Iterated+Salted, SHA-256, AES-256).
// Returns armored PGP block with "-----BEGIN PGP PRIVATE KEY BLOCK-----".
bool ArmorSecretKey(const RsaKeyPair& kp,
                    const std::string& passphrase,
                    std::string& outArmored);

// Extract the public key components from an armored secret key block.
// The passphrase is required to unlock the key.
bool LoadSecretKey(const std::string& armored,
                   const std::string& passphrase,
                   RsaKeyPair& out);

// Extract just the public key MPI bytes (n, e) from an armored secret key block (no passphrase).
bool LoadPublicKeyFromArmored(const std::string& armored,
                               std::vector<uint8_t>& outN,
                               std::vector<uint8_t>& outE);

// ── Symmetric content encryption ─────────────────────────────────────────────

// Encrypt plaintext with AES-256-GCM. Produces a self-contained blob:
//   [12-byte nonce][ciphertext][16-byte tag]
bool AesGcmEncrypt(const std::vector<uint8_t>& key,
                   const uint8_t* plaintext, size_t len,
                   std::vector<uint8_t>& out);

bool AesGcmDecrypt(const std::vector<uint8_t>& key,
                   const uint8_t* ciphertext, size_t len,
                   std::vector<uint8_t>& out);

// Generate 32 random bytes for use as a session key.
bool GenerateSessionKey(std::vector<uint8_t>& out);

// ── PKESK + SEIPD message (armored) ──────────────────────────────────────────

// Encrypt plaintext as an OpenPGP message:
//   - Generate a random AES-256 session key
//   - PKESK packet: session key encrypted with recipient RSA public key (OAEP-SHA1)
//   - SEIPD packet (v1, MDC): AES-256-CFB encrypted literal data
// Returns armored "-----BEGIN PGP MESSAGE-----" block.
bool EncryptMessage(const std::vector<uint8_t>& recipientN,
                    const std::vector<uint8_t>& recipientE,
                    const uint8_t* plaintext, size_t len,
                    std::string& outArmored);

// Decrypt an OpenPGP PKESK+SEIPD message using the RSA private key.
bool DecryptMessage(const std::string& armored,
                    const RsaKeyPair& kp,
                    std::vector<uint8_t>& outPlaintext);

// Decrypt an OpenPGP PKESK+SEIPD message using an X25519 ECDH address key
// (RFC 6637 ECDH KDF + RFC 3394 AES key unwrap, matching Proton's GopenPGP).
bool DecryptMessageEcc(const std::string& armored,
                       const EccKeyPair& kp,
                       std::vector<uint8_t>& outPlaintext);

// ── Signature ────────────────────────────────────────────────────────────────

// Sign data with RSA-PKCS1v15-SHA256, return armored "-----BEGIN PGP SIGNATURE-----".
bool SignDetached(const RsaKeyPair& kp,
                  const uint8_t* data, size_t len,
                  std::string& outArmored);

// ── Name hashing ─────────────────────────────────────────────────────────────

// Compute HMAC-SHA256(hashKey, name_utf8). Returns 32-byte digest.
std::vector<uint8_t> HashNodeName(const std::string& name,
                                   const std::vector<uint8_t>& hashKey);

// Hex-encode bytes.
std::string ToHex(const std::vector<uint8_t>& v);

// ── Base64 helpers ────────────────────────────────────────────────────────────

std::string Base64Encode(const uint8_t* data, size_t len);
bool Base64Decode(const std::string& b64, std::vector<uint8_t>& out);

} // namespace ProtonPGP
