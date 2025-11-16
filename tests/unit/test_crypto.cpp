#include <catch2/catch_test_macros.hpp>
#include "../../include/core/crypto.hpp"

using namespace AdShield::Core;

TEST_CASE("Crypto - Encryption/Decryption", "[crypto]") {
    CryptoEngine crypto;
    
    std::string plaintext = "Hello, World!";
    std::string encrypted = crypto.encrypt(plaintext);
    std::string decrypted = crypto.decrypt(encrypted);
    
    REQUIRE(decrypted == plaintext);
}

TEST_CASE("Crypto - Hashing", "[crypto]") {
    CryptoEngine crypto;
    
    std::string data = "test data";
    std::string hash1 = crypto.hash(data);
    std::string hash2 = crypto.hash(data);
    
    REQUIRE(hash1 == hash2);
    REQUIRE(hash1.length() == 64);  // SHA256 hex length
}

TEST_CASE("Crypto - Different Data Different Hash", "[crypto]") {
    CryptoEngine crypto;
    
    std::string hash1 = crypto.hash("data1");
    std::string hash2 = crypto.hash("data2");
    
    REQUIRE(hash1 != hash2);
}

TEST_CASE("Crypto - Random String Generation", "[crypto]") {
    CryptoEngine crypto;
    
    std::string random1 = crypto.generateRandomString(32);
    std::string random2 = crypto.generateRandomString(32);
    
    REQUIRE(random1.length() == 64);  // 32 bytes = 64 hex chars
    REQUIRE(random1 != random2);
}

TEST_CASE("Crypto - Random Bytes Generation", "[crypto]") {
    CryptoEngine crypto;
    
    auto bytes = crypto.generateRandomBytes(16);
    
    REQUIRE(bytes.size() == 16);
}

TEST_CASE("Crypto - Certificate Verification", "[crypto]") {
    CryptoEngine crypto;
    
    REQUIRE_NOTHROW(crypto.verifyCertificate("/path/to/cert"));
}
