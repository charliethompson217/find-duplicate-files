#include <dirent.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_THREADS 16
#define SIZE_FILEPATH 500

typedef struct {
    char filePath[SIZE_FILEPATH];
    unsigned char hash[SHA256_DIGEST_LENGTH];
} FileData;

pthread_mutex_t lock;
FileData *fileList = NULL;
size_t fileListSize = 0;
bool deleteDuplicates = false;
bool recursiveSearch = false;

void *hash_file(void *arg) {
    char *filePath = (char *)arg;
    FileData data;
    strcpy(data.filePath, filePath);
    unsigned char buf[1024];
    FILE *file = fopen(filePath, "rb");
    if (!file) {
        fprintf(stderr, "Error opening file: %s\n", filePath);
        return NULL;
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    size_t bytesRead = 0;
    while ((bytesRead = fread(buf, 1, sizeof(buf), file)) > 0) {
        SHA256_Update(&sha256, buf, bytesRead);
    }
    SHA256_Final(data.hash, &sha256);

    fclose(file);

    pthread_mutex_lock(&lock);
    if (fileListSize % MAX_THREADS == 0) {
        FileData *newList =
            realloc(fileList, (fileListSize + MAX_THREADS) * sizeof(FileData));
        if (newList == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            exit(EXIT_FAILURE);
        }
        fileList = newList;
    }
    fileList[fileListSize++] = data;
    pthread_mutex_unlock(&lock);

    return NULL;
}

void process_directory(const char *basePath, pthread_t *threads, char (*filePaths)[SIZE_FILEPATH], int *thread_count) {
    DIR *dir;
    struct dirent *entry;
    char path[1024];

    if ((dir = opendir(basePath)) == NULL) {
        fprintf(stderr, "Failed to open directory: %s\n", basePath);
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s", basePath, entry->d_name);

        struct stat statbuf;
        if (stat(path, &statbuf) == 0) {
            if (S_ISDIR(statbuf.st_mode) && recursiveSearch) {
                process_directory(path, threads, filePaths, thread_count);
            } else if (S_ISREG(statbuf.st_mode)) {
                snprintf(filePaths[*thread_count],
                         sizeof(filePaths[*thread_count]), "%s", path);
                pthread_create(&threads[*thread_count], NULL, hash_file, filePaths[*thread_count]);

                (*thread_count)++;
                if (*thread_count >= MAX_THREADS) {
                    for (int i = 0; i < MAX_THREADS; i++) {
                        pthread_join(threads[i], NULL);
                    }
                    *thread_count = 0;
                }
            }
        }
    }

    for (int i = 0; i < *thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    *thread_count = 0;

    closedir(dir);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf(
            "Usage: %s [options] <directory> \n where options include:\n "
            "\t-d\n \t\tdelete duplicates and keep one instance\n"
            "\t-r\n \t\trecursively search subdirectories\n",
            argv[0]);
        return 1;
    }

    char *directoryPath = NULL;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strcmp(argv[i], "-d") == 0) {
                deleteDuplicates = true;
            } else if (strcmp(argv[i], "-r") == 0) {
                recursiveSearch = true;
            }
        } else {
            directoryPath = argv[i];
        }
    }

    pthread_t threads[MAX_THREADS];
    char filePaths[MAX_THREADS][SIZE_FILEPATH];
    int thread_count = 0;
    fileList = malloc(MAX_THREADS * sizeof(FileData));
    if (fileList == NULL) {
        fprintf(stderr, "Initial memory allocation failed\n");
        return 1;
    }

    pthread_mutex_init(&lock, NULL);
    process_directory(directoryPath, threads, filePaths, &thread_count);
    pthread_mutex_destroy(&lock);

    bool *printed = calloc(fileListSize, sizeof(bool));
    if (printed == NULL) {
        fprintf(stderr, "Memory allocation for printed flags failed\n");
        return 1;
    }

    for (size_t i = 0; i < fileListSize; i++) {
        bool found_duplicate = false;
        if (printed[i]) continue;
        for (size_t j = i + 1; j < fileListSize; j++) {
            if (i != j && memcmp(fileList[i].hash, fileList[j].hash, SHA256_DIGEST_LENGTH) == 0) {
                if (!printed[i]) {
                    printf("Duplicate Group:   [SHA-256]  ");
                    for (int k = 0; k < SHA256_DIGEST_LENGTH; k++) {
                        printf("%02x", fileList[i].hash[k]);
                    }
                    printf("\n");
                    printf("  %s\n", fileList[i].filePath);
                    printed[i] = true;
                    found_duplicate = true;
                }
                if (!printed[j]) {
                    printf("  %s\n", fileList[j].filePath);
                    printed[j] = true;
                    if (deleteDuplicates) {
                        if (remove(fileList[j].filePath) != 0) {
                            fprintf(stderr, "Error deleting file: %s\n", fileList[j].filePath);
                        }
                    }
                }
            }
        }

        if (found_duplicate) {
            printf("\n");
        }
    }

    free(printed);
    free(fileList);

    return 0;
}