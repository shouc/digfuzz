#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

// libFuzzer interface is thin, so we don't include any libFuzzer headers.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

#define kMaxAflInputSize (1 * 1024 * 1024)
static uint8_t AflInputBuf[kMaxAflInputSize];

int main(int argc, char **argv) {
    if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(&argc, &argv);
    if (argc > 1) {  // for afl
        size_t l = read(0, AflInputBuf, kMaxAflInputSize);
        LLVMFuzzerTestOneInput(AflInputBuf, l);
    } else
        while (1) { // for qsym
            size_t l = read(0, AflInputBuf, kMaxAflInputSize);
            LLVMFuzzerTestOneInput(AflInputBuf, l);
            printf("EXECDONE\n");
        }
}
