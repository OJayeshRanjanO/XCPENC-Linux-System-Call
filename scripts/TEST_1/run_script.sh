#!/bin/bash
echo "CASE: Testing with input file size of less than page size (27 bytes)\n";
rm -rf encrypt;
rm -rf decrypt;
touch infile;
chmod 777 infile;
echo "ABCDEFGHIJKLMNOPQRSTUVWXYZ" > infile;
cd ../../;
make clean;
make;
./install_module.sh;
./xcpenc -e ./scripts/TEST_1/infile ./scripts/TEST_1/encrypt -p 1234567890123456 16 1;
./xcpenc -d ./scripts/TEST_1/encrypt ./scripts/TEST_1/decrypt -p 1234567890123456 16 1;
cd -;
diff infile decrypt;

