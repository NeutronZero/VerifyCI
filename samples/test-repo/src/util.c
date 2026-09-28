#include <stdlib.h>

typedef struct {
    int status;
    char message[256];
} Result;

Result check_auth(const char *token) {
    Result r;
    r.status = (token != 0);
    return r;
}

int add(int a, int b) {
    return a + b;
}
