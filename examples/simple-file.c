#include <memory_file.h>

#include <stdio.h>
#include <string.h>

int main()
{
    struct memory_file *mf = NULL;

    // Open a sparse file with 32 Gigabytes of storage.
    int ret = mf_open_path(&mf, "./data.bin", 32ull * 1024 * 1024 * 1024, MF_OPEN_NONE);

    if (ret != 0)
    {
        printf("mf_open: failed with %d %s\n", ret, strerror(ret));
        return 1;
    }

    printf("-> Allocated memory file structure at %p\n\n", mf);

    printf("-> Initially:\n");
    printf("   Free: %zd bytes\n", mf_get_free(mf));
    printf("   Allocations: %zd\n", mf_get_allocations(mf));

    const char *s = "Hello world!";
    char *c = mf_alloc(mf, strlen(s) + 1, MF_ALLOC_NONE);

    if (!c)
    {
        printf("mf_alloc: failed to allocate memory\n");
        return 1;
    }

    strcpy(c, s);
    printf("\nCopied string: (%p) %s\n\n", c, c);

    printf("-> Before mf_free:\n");
    printf("   Free: %zd bytes\n", mf_get_free(mf));
    printf("   Allocations: %zd\n", mf_get_allocations(mf));

    mf_free(c);

    printf("-> After mf_free:\n");
    printf("   Free: %zd bytes\n", mf_get_free(mf));
    printf("   Allocations: %zd\n", mf_get_allocations(mf));

    mf_close(&mf);

    return 0;
}