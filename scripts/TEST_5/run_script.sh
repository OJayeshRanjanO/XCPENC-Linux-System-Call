#!/bin/bash
echo "CASE: keybuf != keylen\n";
touch infile;
chmod 777 infile;
tr -dc A-Za-z0-9 </dev/urandom | head -c 10000 > infile
cd ../../;
make clean;
make;
./install_module.sh;
./xcpenc -c ./scripts/TEST_5/infile ./scripts/TEST_5/copy
cd -;
diff infile copy;

