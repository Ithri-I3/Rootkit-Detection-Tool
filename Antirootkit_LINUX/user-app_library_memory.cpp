#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <dirent.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstring>
#include <errno.h>

struct SuspiciousProcess {
    std::string name;
    pid_t pid;
};

bool IsReadableMemoryRegion(void* addr, size_t size) {
    int fd = open("/dev/mem", O_RDONLY);
    if (fd < 0) {
        perror("[-] Failed to open /dev/mem");
        return false;
    }
    void* buffer = malloc(size);
    if (!buffer) {
        close(fd);
        perror("[-] Failed to allocate buffer for memory check");
        return false;
    }
    ssize_t bytesRead = pread(fd, buffer, size, (off_t)addr);
    free(buffer);
    close(fd);
    return bytesRead == (ssize_t)size;
}

bool CheckMaps(pid_t pid, std::vector<std::string>& suspiciousRegions) {
    std::string mapsPath = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream mapsFile(mapsPath);
    if (!mapsFile.is_open()) {
        perror(("[-] Failed to open " + mapsPath).c_str());
        return false;
    }

    std::string line;
    while (std::getline(mapsFile, line)) {
        if (line.find("[anon]") != std::string::npos || line.find("[heap]") != std::string::npos) {
            suspiciousRegions.push_back(line);
        }
    }
    mapsFile.close();
    return true;
}

bool DetectInjectedCode(pid_t pid) {
    std::string memPath = "/proc/" + std::to_string(pid) + "/mem";
    int fd = open(memPath.c_str(), O_RDONLY);
    if (fd < 0) {
        perror(("[-] Failed to open " + memPath).c_str());
        return false;
    }

    char buffer[4096];
    ssize_t bytesRead;
    while ((bytesRead = read(fd, buffer, sizeof(buffer))) > 0) {
        for (ssize_t i = 0; i < bytesRead; ++i) {
            if (buffer[i] == '\xcc') { // Breakpoint instruction
                close(fd);
                return true;
            }
        }
    }
    close(fd);
    return false;
}

void ScanProcesses() {
    DIR* procDir = opendir("/proc");
    if (!procDir) {
        perror("[-] Failed to open /proc directory");
        return;
    }

    dirent* entry;
    std::vector<SuspiciousProcess> suspiciousProcesses;

    while ((entry = readdir(procDir)) != nullptr) {
        if (!isdigit(entry->d_name[0])) continue;

        pid_t pid = std::stoi(entry->d_name);
        std::string exePath = "/proc/" + std::to_string(pid) + "/exe";
        char exeRealPath[PATH_MAX];
        if (readlink(exePath.c_str(), exeRealPath, sizeof(exeRealPath)) < 0) {
            continue;
        }

        std::string exeName = std::string(exeRealPath);
        std::vector<std::string> suspiciousRegions;
        if (CheckMaps(pid, suspiciousRegions) || DetectInjectedCode(pid)) {
            suspiciousProcesses.push_back({exeName, pid});
            std::cout << "[!] Suspicious Process Detected: " << exeName << " (PID: " << pid << ")\n";
            for (const auto& region : suspiciousRegions) {
                std::cout << "    Suspicious Region: " << region << "\n";
            }
        }
    }

    closedir(procDir);
}

void ScanMemory() {
    std::cout << "[+] Scanning system memory for suspicious regions...\n";

    std::ifstream memInfoFile("/proc/meminfo");
    if (!memInfoFile.is_open()) {
        perror("[-] Failed to open /proc/meminfo");
        return;
    }

    std::vector<std::string> suspiciousRegions;
    std::string mapsPath = "/proc/self/maps"; // Scan the current process memory as an example
    std::ifstream mapsFile(mapsPath);
    if (!mapsFile.is_open()) {
        perror(("[-] Failed to open " + mapsPath).c_str());
        return;
    }

    std::string line;
    while (std::getline(mapsFile, line)) {
        if (line.find("[anon]") != std::string::npos || line.find("[heap]") != std::string::npos ||
            line.find("[stack]") != std::string::npos || line.find("[vdso]") != std::string::npos) {
            suspiciousRegions.push_back(line);
            }
    }
    mapsFile.close();

    if (suspiciousRegions.empty()) {
        std::cout << "[+] No suspicious memory regions found.\n";
    } else {
        for (const auto& region : suspiciousRegions) {
            std::cout << "[!] Suspicious Memory Region: " << region << "\n";
        }
    }
}

int main() {
    std::cout << "\n[+] Starting rootkit detection...\n";

    // Process Scanning
    std::cout << "\n[*] Scanning for suspicious processes...\n";
    ScanProcesses();

    // Memory Scanning
    std::cout << "\n[*] Scanning memory regions...\n";
    ScanMemory();

    std::cout << "\n[+] Rootkit detection completed.\n";

    return 0;
}
