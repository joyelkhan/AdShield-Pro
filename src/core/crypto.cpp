#include "../../include/core/crypto.hpp"
#include "../../include/core/logger.hpp"
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iomanip>
#include <sstream>
#include <fstream>

namespace AdShield {
namespace Core {

CryptoEngine::CryptoEngine() {
    Logger::getInstance().info("Initializing Crypto Engine");
    initializeKeys();
}

void CryptoEngine::initializeKeys() {
    // Generate keys - in production, these would be properly randomized
    std::string key_seed = "ADSHIELD_ULTRA_CRYPTO_KEY_2024";
    std::string iv_seed = "ADSHIELD_IV_16B";
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(key_seed.c_str()), 
           key_seed.length(), hash);
    
    memcpy(aes_key, hash, 32);
    memcpy(aes_iv, iv_seed.c_str(), 16);
}

std::string CryptoEngine::encrypt(const std::string& plaintext) {
    AES_KEY encrypt_key;
    AES_set_encrypt_key(aes_key, 256, &encrypt_key);
    
    std::string ciphertext;
    ciphertext.resize(plaintext.length() + AES_BLOCK_SIZE);
    
    int num = 0;
    unsigned char ecount_buf[AES_BLOCK_SIZE];
    memset(ecount_buf, 0, AES_BLOCK_SIZE);
    
    AES_ctr128_encrypt(
        reinterpret_cast<const unsigned char*>(plaintext.c_str()),
        reinterpret_cast<unsigned char*>(&ciphertext[0]),
        plaintext.length(),
        &encrypt_key,
        aes_iv,
        ecount_buf,
        &num
    );
    
    ciphertext.resize(plaintext.length());
    return ciphertext;
}

std::string CryptoEngine::decrypt(const std::string& ciphertext) {
    // CTR mode is symmetric
    return encrypt(ciphertext);
}

std::string CryptoEngine::hash(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), 
           data.length(), hash);
    
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    
    return oss.str();
}

std::string CryptoEngine::hashFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        Logger::getInstance().error("Failed to open file for hashing: " + filepath);
        return "";
    }
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    
    const size_t BUFFER_SIZE = 65536;
    char buffer[BUFFER_SIZE];
    
    while (file.read(buffer, BUFFER_SIZE)) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);
    
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    
    return oss.str();
}

std::string CryptoEngine::generateRandomString(size_t length) {
    std::vector<unsigned char> bytes = generateRandomBytes(length);
    std::ostringstream oss;
    
    for (unsigned char byte : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    
    return oss.str();
}

std::vector<unsigned char> CryptoEngine::generateRandomBytes(size_t length) {
    std::vector<unsigned char> buffer(length);
    
    if (RAND_bytes(buffer.data(), length) != 1) {
        Logger::getInstance().error("Failed to generate random bytes");
    }
    
    return buffer;
}

bool CryptoEngine::verifyCertificate(const std::string& cert_path) {
    // Placeholder for certificate verification
    Logger::getInstance().info("Verifying certificate: " + cert_path);
    return true;
}

bool CryptoEngine::validateSignature(const std::string& data, const std::string& signature) {
    // Placeholder for signature validation
    return true;
}

} // namespace Core
} // namespace AdShield
