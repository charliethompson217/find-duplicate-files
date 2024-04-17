
# File Duplicate Finder

## Overview
This program scans a directory for duplicate files based on their SHA-256 hash. It's designed to be highly efficient, utilizing multithreading to handle a large number of files simultaneously. The program can optionally delete duplicates, keeping only one instance of each file, and can recursively search through subdirectories.

## Compilation
Make sure to link the pthread and OpenSSL libraries:
```
gcc -o find_duplicates find_duplicates.c -lpthread -lcrypto
```

## Usage

Run the program with the following command:
```
./find_duplicates [options] <directory>
```

### Options
- `-d`: Delete duplicates, only keep one instance.
- `-r`: Recursively search through subdirectories.

## Requirements
- OpenSSL: Required for SHA-256 hashing.
- POSIX compatible environment: Because of pthreads and directory handling.

## Example
To search for duplicates in the `/path/to/directory` directory recursively and delete duplicates:
```
./find_duplicates -r -d /path/to/directory
```

