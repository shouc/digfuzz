#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

typedef char string[8];

int target(const char* s1, size_t s) {
    if (s < 8) return -1;
    int i;

    const char* s2 = "abcdefgx";
    if(*s1) {
        if (*s1 == *s2) {
            s1++;
            s2++;
            if(*s1) {
                if (*s1 == *s2) {
                    s1++;
                    s2++;
                    if(*s1) {
                        if (*s1 == *s2) {
                            s1++;
                            s2++;
                            if(*s1) {
                                if (*s1 == *s2) {
                                    s1++;
                                    s2++;
                                    if(*s1) {
                                        if (*s1 == *s2) {
                                            s1++;
                                            s2++;
                                            if(*s1) {
                                                if (*s1 == *s2) {
                                                    s1++;
                                                    s2++;
                                                    if(*s1) {
                                                        if (*s1 == *s2) {
                                                            s1++;
                                                            s2++;
                                                            if(*s1) {
                                                                if (*s1 == *s2) {
                                                                    assert(0);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size){
    target(Data, Size);
    return 0;
}