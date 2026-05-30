#!/bin/bash
mkdir -p cpp_version/payload/nlohmann
curl -L https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp -o cpp_version/payload/nlohmann/json.hpp
curl -L https://www.sqlite.org/2024/sqlite-amalgamation-3460000.zip -o sqlite.zip
unzip sqlite.zip
cp sqlite-amalgamation-3460000/sqlite3.c sqlite-amalgamation-3460000/sqlite3.h cpp_version/payload/
rm -rf sqlite.zip sqlite-amalgamation-3460000
echo "Dependencies downloaded successfully."
