#!/bin/bash
echo "CASE: keybuf != keylen\n";
touch infile;
chmod 777 infile;
tr -dc A-Za-z0-9 </dev/urandom | head -c 10000 > infile
cd ../../;
make clean;
make;
./install_module.sh;
./xcpenc -e ./scripts/TEST_4/infile ./scripts/TEST_4/encrypt -p 1234567890 16 1
cd -;
diff infile decrypt;

