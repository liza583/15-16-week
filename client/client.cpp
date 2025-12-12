#include <iostream>
#include <string>
#include <thread>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>
#include <atomic>
#include <cmath>
#include <chrono>
#include <vector>
#include <future>
#include <algorithm>

// Определяем длину хеша MD5
#define MD5_DIGEST_LENGTH 16

// --- password_cracker.hpp ---
extern unsigned char targetMD5[MD5_DIGEST_LENGTH];
void computeMD5FromString(const std::string &str, unsigned char *result);
std::string md5ToString(unsigned char *md);
void bruteForceMD5Thread(int threadId, const std::string &targetMD5, const std::string &chars, int len, long long startIdx, long long endIdx, int client_socket, std::atomic<bool> &found, std::atomic<bool> &password_found);
void bruteForceMD5(const std::string &targetMD5, int numThreads, int len, int client_socket, std::atomic<bool> &found, std::atomic<bool> &password_found);

// --- password_cracker.cpp ---
unsigned char targetMD5[MD5_DIGEST_LENGTH];
std::atomic<bool> found(false);
std::atomic<bool> password_found(false);
std::atomic<long long> totalCombinations(0);

void computeMD5FromString(const std::string &str, unsigned char *result) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    EVP_DigestUpdate(mdctx, str.c_str(), str.length());
    EVP_DigestFinal_ex(mdctx, result, NULL);
    EVP_MD_CTX_free(mdctx);
}

std::string md5ToString(unsigned char *md) {
    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)md[i];
    }
    return ss.str();
}

void bruteForceMD5Thread(int threadId, const std::string &targetMD5, const std::string &chars, int len, long long startIdx, long long endIdx, int client_socket, std::atomic<bool> &found, std::atomic<bool> &password_found) {
    if (found.load() || password_found.load()) {
        return;
    }
    unsigned char result[MD5_DIGEST_LENGTH];

    for (long long index = startIdx; index < endIdx; ++index) {
        if (found.load() || password_found.load()) {
            return;
        }

        std::string currentStr;
        long long tempIndex = index;
        if (len == 0) {
            std::string emptyStr = "";
            computeMD5FromString(emptyStr, result);
            std::string computedMD5 = md5ToString(result);
            if (computedMD5 == targetMD5) {
                password_found.store(true);
                std::cout << "Thread " << threadId << ": Found password: " << "" << std::endl;
                send(client_socket, emptyStr.c_str(), emptyStr.length(), 0);
                 
                return;
            }
            continue;
        }

        for (int i = 0; i < len; i++) {
            currentStr = chars[tempIndex % chars.size()] + currentStr;
            tempIndex /= chars.size();
        }

        computeMD5FromString(currentStr, result);
        std::string computedMD5 = md5ToString(result);
        if (computedMD5 == targetMD5) {
            password_found.store(true);
            std::cout << "Thread " << threadId << ": Found password: " << currentStr << std::endl;
            send(client_socket, currentStr.c_str(), currentStr.length(), 0);
            return;
        }
    }
}

void bruteForceMD5(const std::string &targetMD5, int numThreads, int len, int client_socket, std::atomic<bool> &found, std::atomic<bool> &password_found) {
    const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    std::vector<std::thread> threads;
    for (int i = 0; i < numThreads; ++i) {
        threads.push_back(std::thread(bruteForceMD5Thread, i, std::ref(targetMD5), std::ref(chars), len, 0, pow(chars.size(), len), client_socket, std::ref(found), std::ref(password_found)));
    }

    for (auto &t : threads) {
        t.join();
    }
}

// --- Main Client (Worker) ---
int main() {
    int client_socket;
    const char* SERVER_IP = "192.168.1.1";
    const int PORT = 8080;
    int numThreads = 0;
    std::atomic<bool> found(false);
    std::atomic<bool> password_found(false);

    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        std::cerr << "Не удалось создать сокет!" << std::endl;
        return -1;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        std::cerr << "Не удалось подключиться к серверу!" << std::endl;
        close(client_socket);
        return -1;
    }
    char buffer[1024];
    int bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
        std::cerr << "Сервер отключен!" << std::endl;
        close(client_socket);
        return -1;
    }
    buffer[bytes_received] = '\0';
    std::string message = buffer;
    std::stringstream ss(message);
    std::string targetMD5String;
    int len;
    ss >> targetMD5String >> len;
    numThreads = std::thread::hardware_concurrency();
    if (numThreads == 0) {
        numThreads = 4;
    }
    std::cout << "Воркер использует " << numThreads << " потоков." << std::endl;

    while (!found.load() && !password_found.load()) {
        bruteForceMD5(targetMD5String, numThreads, len, client_socket, std::ref(found), std::ref(password_found));
        if (!found.load() && !password_found.load()) {
            std::string not_found = "not found";
            send(client_socket, not_found.c_str(), not_found.length(), 0);

            bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
            if (bytes_received <= 0) {
                close(client_socket);
                std::cout << "воркер завершил работу" << std::endl;
                break;
            }
            buffer[bytes_received] = '\0';
            message = buffer;
            if (message == "Пароль найден всем спасибо") {
                found.store(true);
                close(client_socket);
                std::cout << "воркер завершил работу" << std::endl;
                break;
            } else if (message == "close") {
                close(client_socket);
                std::cout << "воркер завершил работу" << std::endl;
                break;
            } else {
                std::stringstream ss(message);
                ss >> targetMD5String >> len;
            }
        }
    }
    bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        std::string close_message = buffer;
        if (close_message == "close") {
            close(client_socket);
            std::cout << "воркер завершил работу" << std::endl;
        }
    } else if (bytes_received == 0) {
        close(client_socket);
        std::cout << "воркер завершил работу" << std::endl;
    }
    return 0;
}
