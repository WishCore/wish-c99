#!/usr/bin/awk -f

# This program makes it easier to import buffers from Node 
# (output of buffer.toString('hex')) as an array in C program source. 
# It works by inserting "0x" before every 2 characters read.

{ while (i < length) { printf("0x%s, ", substr($0,1+i,2)); i+=2} }

