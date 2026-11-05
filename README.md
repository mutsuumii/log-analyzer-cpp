# log-analyzer-cpp ⚡

Security log analyzer in pure C++20. Parses Apache/Nginx access logs and detects:
- SQL injection attempts
- XSS attempts
- Path traversal
- Sensitive file access
- Command execution attempts
- Admin panel probes

## Build
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/log_analyzer /var/log/nginx/access.log
```

## License
MIT
