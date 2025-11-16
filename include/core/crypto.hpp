#pragma once

#include <string>
#include <vector>
#include <memory>

namespace AdShield {
namespace Core {

/**
 * @class CryptoEngine
 * @brief Cryptographic operations for data protection
 * 
 * Provides:
 * - AES-256-CTR encryption/decryption
 * - SHA-256 hashing
 * - Secure random number generation
 * - Certificate handling
 */
class CryptoEngine {
public:
    CryptoEngine();
    ~CryptoEngine();

    // Encryption/Decryption
    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);
    
    // Hashing
    std::string hash(const std::string& data);
    std::string hashFile(const std::string& filepath);
    
    // Random generation
    std::string generateRandomString(size_t length);
    std::vector<unsigned char> generateRandomBytes(size_t length);
    
    // Certificate operations
    bool verifyCertificate(const std::string& cert_path);
    bool validateSignature(const std::string& data, const std::string& signature);

private:
    unsigned char aes_key[32];
    unsigned char aes_iv[16];
    
    void initializeKeys();
};

} // namespace Core
} // namespace AdShield
