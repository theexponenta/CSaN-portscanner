#include <cstdlib>
#include <cstring>
#include "random.h"


int randInt(int from, int to) {
    return from + rand() % (to - from + 1);
}


void randBytes(const void* buffer, int count) {
    int *ptr = (int*)buffer;
    while (count > sizeof(int)) {
        *ptr = rand();
        count -= sizeof(int);
        ptr++;
    }

    int remainderRand = rand();
    memcpy(ptr, &remainderRand, count);
}
