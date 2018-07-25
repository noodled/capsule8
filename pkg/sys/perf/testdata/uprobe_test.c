#include <stdio.h>

static void
some_function(const char *string) {
    printf("some_function: %s\n", string);
}

int
main(int argc, char *argv[]) {
    some_function(argv[0]);
    return 0;
}
