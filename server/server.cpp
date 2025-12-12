#include <iostream>
#include <string>
#include <thread>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <vector>
#include <mutex>
#include <stdexcept>
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>
#include <atomic>
#include <cmath>
#include <queue>
#include <csignal>
#include <cstdlib>
#include <algorithm>

// --- Global Variables ---
std::vector<std::string> message_history;
std::mutex history_mutex;
#define MD5_DIGEST_LENGTH 16

// --- password_cracker.hpp ---
extern unsigned char targetMD5[MD5_DIGEST_LENGTH];
void computeMD5FromString(const std::string &str, unsigned char *result);
std::string md5ToString(unsigned char *md);

// --- password_cracker.cpp ---
unsigned char targetMD5[MD5_DIGEST_LENGTH];

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

// --- Function Declarations ---
void create_socket(int& socket_fd);
void bind_socket(int socket_fd, sockaddr_in& server_addr);
void listen_socket(int socket_fd);

// --- Global Variables for Signal Handling ---
int server_socket_global = -1;
std::vector<int> clients_global;
std::mutex clients_mutex_global;
std::atomic<bool> server_running(true);


void signalHandler(int signum) {
    if (signum == SIGINT) {
        std::cout << "Сервер получил сигнал SIGINT (Ctrl+C). Завершаем работу..." << std::endl;
        server_running = false;

        // 1. Находим PIDы воркеров
        std::string pgrep_command = "pgrep client";
        std::string pids_str = "";
        FILE* pgrep_output = popen(pgrep_command.c_str(), "r");
        if (pgrep_output) {
            char buffer[128];
            while (fgets(buffer, sizeof(buffer), pgrep_output) != nullptr) {
                pids_str += buffer;
            }
            pclose(pgrep_output);
        }

        std::vector<int> worker_pids;
        std::stringstream ss(pids_str);
        int pid;
        while (ss >> pid) {
            worker_pids.push_back(pid);
        }

        // 2. Убиваем воркеров
         for(int pid : worker_pids){
           std::string kill_command = "kill " + std::to_string(pid);
           system(kill_command.c_str());
         }

        // 3. Закрываем все сокеты
        if (server_socket_global != -1) {
            close(server_socket_global);
        }
        {
             std::lock_guard<std::mutex> guard(clients_mutex_global);
             for(int client_socket : clients_global) {
               close(client_socket);
            }
        }
         std::cout << "Сервер завершил работу." << std::endl;
        exit(0); // Завершаем работу сервера
    }
}


// --- Main Server ---
int main() {
    int server_socket, client_socket;
    sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    const int PORT = 8080;
    const int MAX_WORKERS = 5;
    const int MAX_PASSWORD_LENGTH = 8; // Ограничение длины пароля
    std::vector<int> clients;
    std::vector<std::thread> workerThreads;
    std::mutex clients_mutex;
    std::atomic<bool> found(false);
    std::string found_password;
    std::string password;
    std::queue<int> availableLengths;

    for (int i = 1; i <= MAX_PASSWORD_LENGTH; ++i) {
        availableLengths.push(i);
    }
    
      // Устанавливаем обработчик сигнала SIGINT
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = signalHandler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    try {
        std::cout << "Введите пароль: ";
        std::cin >> password;

        create_socket(server_socket);
        server_socket_global = server_socket;

        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(PORT);
        server_addr.sin_addr.s_addr = INADDR_ANY;

        bind_socket(server_socket, server_addr);
        listen_socket(server_socket);

        std::cout << "Сервер запущен, ожидаем подключения воркеров..." << std::endl;

        computeMD5FromString(password, targetMD5);
        std::string targetMD5String = md5ToString(targetMD5);

        int worker_count = 0;
        while (worker_count < MAX_WORKERS && server_running.load()) {
            client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
            if (client_socket == -1) {
                if (worker_count > 0) {
                    break;
                } else {
                    throw std::runtime_error("Ошибка при принятии подключения!");
                }
            }

            {
                std::lock_guard<std::mutex> guard(clients_mutex);
                 clients_global.push_back(client_socket);
                clients.push_back(client_socket);
            }

            int currentLength = 0;
            if (!availableLengths.empty()) {
                currentLength = availableLengths.front();
                availableLengths.pop();
            } else {
                std::string close_message = "close";
                send(client_socket, close_message.c_str(), close_message.length(), 0);
                close(client_socket);
                continue;
            }
            // Отправляем хеш и длину пароля
            std::string message = targetMD5String + " " + std::to_string(currentLength);
            send(client_socket, message.c_str(), message.length(), 0);

            std::cout << "Worker " << worker_count + 1 << " подключен. Длина:" << currentLength << std::endl;

            workerThreads.push_back(std::thread([client_socket, &found, &found_password, &clients, &clients_mutex, &availableLengths, targetMD5String, worker_count]() {
                char buffer[1024];
                while (true) {
                    int bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
                    if (bytes_received <= 0) {
                        break;
                    }
                    buffer[bytes_received] = '\0';
                    std::string message = buffer;
                    if (message == "not found") {
                        int currentLength = 0;
                        if (!availableLengths.empty()) {
                            currentLength = availableLengths.front();
                            availableLengths.pop();
                        } else {
                            std::string close_message = "close";
                            send(client_socket, close_message.c_str(), close_message.length(), 0);
                            close(client_socket);
                            break;
                        }
                        // Проверка на максимальную длину
                        if (currentLength > MAX_PASSWORD_LENGTH) {
                            std::string close_message = "close";
                            send(client_socket, close_message.c_str(), close_message.length(), 0);
                            close(client_socket);
                            break;
                        }

                        message = targetMD5String + " " + std::to_string(currentLength);
                        send(client_socket, message.c_str(), message.length(), 0);
                        std::cout << "Воркер " << worker_count + 1 << " запросил следующую длину, выдаю:" << currentLength << std::endl;
                    } else if (message != "close" && message != "not found" && !message.empty()) {
                        found.store(true);
                        found_password = message;
                        std::cout << "Пароль найден: " << found_password << std::endl;
                        
                        {
                            std::lock_guard<std::mutex> guard(clients_mutex);
                            for (int client_socket : clients) {
                                std::string found_message = "Пароль найден всем спасибо";
                                send(client_socket, found_message.c_str(), found_message.length(), 0);
                            }
                        }
                        break;
                    } else if (message == "close") {
                        close(client_socket);
                        break;
                    }
                }
            }));
            worker_count++;
        }

        while (!found.load() && server_running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        {
            std::lock_guard<std::mutex> guard(clients_mutex);
             for (int client_socket : clients) {
                 close(client_socket);
            }
            clients.clear();

        }

         close(server_socket);

        std::cout << "Сервер завершает работу" << std::endl;
    } catch (const std::runtime_error& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        if (server_socket != -1) {
            close(server_socket);
        }
        return -1;
    }

    return 0;
}

// Функция для работы с сокетами
void create_socket(int& socket_fd) {
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        throw std::runtime_error("Не удалось создать сокет!");
    }
}

// Функция для привязки сокета
void bind_socket(int socket_fd, sockaddr_in& server_addr) {
    if (bind(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        throw std::runtime_error("Не удалось привязать сокет!");
    }
}

// Функция для начала прослушивания сокета
void listen_socket(int socket_fd) {
    if (listen(socket_fd, 0) == -1) {
        throw std::runtime_error("Не удалось начать прослушивание!");
    }
}
