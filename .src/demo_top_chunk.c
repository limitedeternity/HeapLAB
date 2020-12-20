#include <stdlib.h>

int main(int argc, char* argv[]) {

    void* a = malloc(9);

    malloc(1);
    malloc(0);

    malloc(24);
    malloc(25);

    return 0;
}
