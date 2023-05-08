#!/bin/bash

cp -f ./run.sh ../run.sh;
rm -rf *;
cp -f ../run.sh ./run.sh;
rm -f ../run.sh;
cmake ../;
make;
make install;
cp -f ./run.sh ../run.sh;
rm -rf *;
cp -f ../run.sh ./run.sh;
rm -f ../run.sh;