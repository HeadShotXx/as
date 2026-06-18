#!/bin/bash
mkdir -p cpp_version/injector/src cpp_version/proxydll/src

# Download nlohmann/json
curl -L https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp -o cpp_version/injector/src/json.hpp
cp cpp_version/injector/src/json.hpp cpp_version/proxydll/src/json.hpp

# Download SQLite amalgamation
curl -L https://www.sqlite.org/2023/sqlite-amalgamation-3420000.zip -o sqlite.zip
unzip -j sqlite.zip sqlite-amalgamation-3420000/sqlite3.c sqlite-amalgamation-3420000/sqlite3.h -d cpp_version/proxydll/src/
rm sqlite.zip
