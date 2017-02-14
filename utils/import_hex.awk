#!/usr/bin/awk -f

# This can be used to import a Node.js buffer (.toString('hex')). The
# resulting raw data is printed to stdout
#
# A BSON buffer saved to disk with this script can be opened in a C program
# using the cBSON library, or it can be examined using "bson-to-json" 
# utility which is available as an example program 
# from https://github.com/mongodb/libbson.git
#
# Usage awk -f import_contact.awk >contact.bson

{ while (i < length) { printf("%c", strtonum("0x" substr($0,1+i,2))); i+=2} }

