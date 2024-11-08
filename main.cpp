#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <cstring>

// Функция для обработки ошибок OpenSSL
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Функция для генерации ключа и IV из пароля
void deriveKeyAndIV(const std::string& password, unsigned char* key, unsigned char* iv) {
    const unsigned char* salt = reinterpret_cast<const unsigned char*>("salt");
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), salt, 4, 10000, EVP_sha256(), 32, key)) {
        handleErrors();
    }
    RAND_bytes(iv, EVP_CIPHER_iv_length(EVP_aes_256_cbc())); // Генерация случайного IV
}

// Функция для шифрования файла
void encrypt(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    std::ifstream in(inputFile, std::ios::binary);
    std::ofstream out(outputFile, std::ios::binary);

    unsigned char key[32];
    unsigned char iv[16];
    deriveKeyAndIV(password, key, iv);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) handleErrors();

    // Записываем IV в начало файла для последующей расшифровки
    out.write(reinterpret_cast<char*>(iv), sizeof(iv));

    std::vector<unsigned char> buffer(4096);
    std::vector<unsigned char> cipherBuffer(4096 + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int bytesRead, cipherBytes;

    while (in.read(reinterpret_cast<char*>(buffer.data()), buffer.size())) {
        bytesRead = in.gcount();
        if (EVP_EncryptUpdate(ctx, cipherBuffer.data(), &cipherBytes, buffer.data(), bytesRead) != 1) {
            handleErrors();
        }
        out.write(reinterpret_cast<char*>(cipherBuffer.data()), cipherBytes);
    }

    if (EVP_EncryptFinal_ex(ctx, cipherBuffer.data(), &cipherBytes) != 1) handleErrors();
    out.write(reinterpret_cast<char*>(cipherBuffer.data()), cipherBytes);

    EVP_CIPHER_CTX_free(ctx);
    std::cout << "Encryption completed!" << std::endl;
}

// Функция для расшифровки файла
void decrypt(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    std::ifstream in(inputFile, std::ios::binary);
    std::ofstream out(outputFile, std::ios::binary);

    unsigned char key[32];
    unsigned char iv[16];
    deriveKeyAndIV(password, key, iv);

    // Читаем IV из файла
    in.read(reinterpret_cast<char*>(iv), sizeof(iv));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) handleErrors();

    std::vector<unsigned char> buffer(4096);
    std::vector<unsigned char> plainBuffer(4096 + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int bytesRead, plainBytes;

    while (in.read(reinterpret_cast<char*>(buffer.data()), buffer.size())) {
        bytesRead = in.gcount();
        if (EVP_DecryptUpdate(ctx, plainBuffer.data(), &plainBytes, buffer.data(), bytesRead) != 1) {
            handleErrors();
        }
        out.write(reinterpret_cast<char*>(plainBuffer.data()), plainBytes);
    }

    if (EVP_DecryptFinal_ex(ctx, plainBuffer.data(), &plainBytes) != 1) handleErrors();
    out.write(reinterpret_cast<char*>(plainBuffer.data()), plainBytes);

    EVP_CIPHER_CTX_free(ctx);
    std::cout << "Decryption completed!" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <encrypt/decrypt> <inputfile> <outputfile> <password>" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string inputFile = argv[2];
    std::string outputFile = argv[3];
    std::string password = argv[4];

    try {
        if (mode == "encrypt") {
            encrypt(inputFile, outputFile, password);
        } else if (mode == "decrypt") {
            decrypt(inputFile, outputFile, password);
        } else {
            std::cerr << "Invalid mode. Use 'encrypt' or 'decrypt'." << std::endl;
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}
