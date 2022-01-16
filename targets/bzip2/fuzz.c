#include "bzlib.h"
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

extern int BZ2_bzBuffToBuffDecompress(char* dest,
                                      unsigned int* destLen,
                                      char*         source,
                                      unsigned int  sourceLen,
                                      int           small,
                                      int           verbosity);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int r, small;
    unsigned int nZ, nOut;

    // See: https://github.com/google/bzip2-rpc/blob/master/unzcrash.c#L39
    nOut = size*2;
    char *outbuf = malloc(nOut);
    small = size % 2;
    r = BZ2_bzBuffToBuffDecompress(outbuf, &nOut, (char *)data, size,
            small, /*verbosity=*/0);

    if (r != BZ_OK) {
#ifdef __DEBUG__
        fprintf(stdout, "Decompression error: %d\n", r);
#endif
    }
    free(outbuf);
    return 0;
}