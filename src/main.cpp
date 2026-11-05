#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <map>
#include <vector>
#include <algorithm>
#include <sstream>

struct LogEntry {
    std::string ip;
    std::string timestamp;
    std::string method;
    std::string path;
    int status = 0;
};

struct ThreatHit {
    std::string type;
    std::string ip;
    std::string path;
    std::string time;
};

static const std::vector<std::pair<std::regex, std::string>> THREAT_PATTERNS = {
    {std::regex(R"(union\s+select|or\s+1\s*=\s*1|drop\s+table)", std::regex::icase), "SQL Injection"},
    {std::regex(R"(<script|javascript:|onerror=|onload=)", std::regex::icase), "XSS"},
    {std::regex(R"(\.\./\.\./|%2e%2e%2f)"), "Path Traversal"},
    {std::regex(R"(etc/passwd|etc/shadow|win\.ini)", std::regex::icase), "Sensitive File Access"},
    {std::regex(R"(cmd\.exe|powershell|/bin/sh)", std::regex::icase), "Command Execution"},
    {std::regex(R"(wp-admin|wp-login|phpmyadmin)", std::regex::icase), "Admin Panel Probe"},
};

static const std::regex LOG_REGEX(
    R"(^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+))"
);

LogEntry parse_line(const std::string& line) {
    LogEntry entry;
    std::smatch m;
    if (std::regex_search(line, m, LOG_REGEX)) {
        entry.ip = m[1];
        entry.timestamp = m[2];
        entry.method = m[3];
        entry.path = m[4];
        entry.status = std::stoi(m[5]);
    }
    return entry;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: log_analyzer <access.log>\n";
        return 1;
    }

    std::ifstream file(argv[1]);
    if (!file.is_open()) {
        std::cerr << "Cannot open: " << argv[1] << "\n";
        return 1;
    }

    std::map<std::string, int> ip_count;
    std::map<int, int> status_count;
    std::vector<ThreatHit> threats;
    int total = 0, failed_auth = 0;

    std::string line;
    while (std::getline(file, line)) {
        auto entry = parse_line(line);
        if (entry.ip.empty()) continue;
        total++;
        ip_count[entry.ip]++;
        status_count[entry.status]++;
        if (entry.status == 401 || entry.status == 403) failed_auth++;

        for (auto& [pattern, label] : THREAT_PATTERNS) {
            if (std::regex_search(entry.path, pattern)) {
                threats.push_back({label, entry.ip, entry.path, entry.timestamp});
            }
        }
    }

    // Sort IPs by count
    std::vector<std::pair<std::string, int>> sorted_ips(ip_count.begin(), ip_count.end());
    std::sort(sorted_ips.begin(), sorted_ips.end(),
        [](auto& a, auto& b) { return a.second > b.second; });

    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "  SECURITY LOG ANALYSIS\n";
    std::cout << std::string(60, '=') << "\n";
    std::cout << "Total requests:  " << total << "\n";
    std::cout << "Unique IPs:      " << ip_count.size() << "\n";
    std::cout << "Failed auth:     " << failed_auth << "\n";

    std::cout << "\n--- Top 10 IPs ---\n";
    int shown = 0;
    for (auto& [ip, cnt] : sorted_ips) {
        if (shown++ >= 10) break;
        std::cout << "  " << ip << "  " << cnt << " req"
                  << (cnt > 100 ? " [!]" : "") << "\n";
    }

    if (!threats.empty()) {
        std::cout << "\n--- THREATS ---\n";
        for (auto& t : threats) {
            std::cout << "  [" << t.type << "] IP: " << t.ip
                      << "  Path: " << t.path << "\n";
        }
    } else {
        std::cout << "\nNo threat patterns detected.\n";
    }

    return 0;
}
