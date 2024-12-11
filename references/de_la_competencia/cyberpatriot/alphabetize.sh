#!/bin/bash

# Check if a file was provided as an argument
if [ $# -ne 1 ]; then
    echo "Usage: $0 <filename>"
    exit 1
fi

# Check if the file exists
if [ ! -f "$1" ]; then
    echo "Error: File '$1' not found."
    exit 1
fi

# Sort the file contents and print them
echo "Sorted usernames from file '$1':"
sort "$1"
