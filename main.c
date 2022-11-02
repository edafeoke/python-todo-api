#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

/**
 * @brief Main - Entry point
 * return 1 success
 */
int main()
{
    char *line = malloc(sizeof(char*));
    ssize_t buffer = 0;

    printf("Installing Backend Base Project...\n");
    getline(&line, buffer, stdin);
    printf("%s\n",line);

    free(line);
    return (0);
}