#!/bin/bash
rules=$1

make

# Run with rules
./killchain $rules