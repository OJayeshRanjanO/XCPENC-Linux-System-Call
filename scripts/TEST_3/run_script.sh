#!/bin/bash
echo "CASE: Testing with input file size of 10000 bytes\n";
rm -rf encrypt;
rm -rf decrypt;
touch infile;
chmod 777 infile;
tr -dc A-Za-z0-9 </dev/urandom | head -c 10000 > infile
cd ../../;
make clean;
make;
./install_module.sh;
./xcpenc -e ./scripts/TEST_3/infile ./scripts/TEST_3/encrypt -p 1234567890123456 16 1;
./xcpenc -d ./scripts/TEST_3/encrypt ./scripts/TEST_3/decrypt -p 1234567890123456 16 1;
cd -;
diff infile decrypt;

