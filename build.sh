#!/usr/bin/env bash

cd SysidentKernel
cmake .
make
cd ..

cd SysidentUser
cmake .
make
cd ..