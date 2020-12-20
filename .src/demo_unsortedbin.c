#include <stdlib.h>

int main(int argc, char* argv[]) {
    void* a = malloc(0x88);
    void* b = malloc(0x88);

    free(b);

    b = malloc(0x88);
    malloc(0x18);

    free(a);
    free(b);

    return 0;
}
