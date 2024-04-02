#include "memory_file.h"

#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>

struct memory_file_region;

struct memory_file
{
#ifndef MEMFILE_NO_MUTEX
    bool has_mutex;
    pthread_mutex_t mtx;
#endif

    void *data;
    size_t total_size;
    size_t free;
    struct memory_file_region *regions;
    struct memory_file_region *allocate_next;
    size_t regions_allocated;
};

struct memory_file_region
{
    struct memory_file_region *prev;
    struct memory_file_region *next;

    void *ptr;
    size_t length;

    struct memory_file *mf;

    uint8_t used : 1;
    uint8_t zero_on_free : 1;
};

static inline size_t mf_align_size(size_t size)
{
    if (size % 16 == 0)
        return size;

    size += 16 - (size & (16 - 1));
    return size;
}

static inline int mf_lock(struct memory_file *mf)
{
#ifndef MEMFILE_NO_MUTEX
    if (!mf->has_mutex)
        return 0;

    return pthread_mutex_lock(&mf->mtx);
#else
    return 0;
#endif
}

static inline void mf_unlock(struct memory_file *mf)
{
#ifndef MEMFILE_NO_MUTEX
    if (!mf->has_mutex)
        return;

    pthread_mutex_unlock(&mf->mtx);
#endif
}

int mf_open_fd(struct memory_file **mf, int fd, size_t requested_size, int flags)
{
    const size_t control_block_size = mf_align_size(sizeof(struct memory_file));
    const size_t header_size = mf_align_size(sizeof(struct memory_file_region));

    if (requested_size < (control_block_size + header_size) || requested_size > INT64_MAX)
        return -ENOMEM;

    void *data = mmap(NULL, requested_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_SHARED_VALIDATE | MAP_NORESERVE, fd, 0);

    if (data == MAP_FAILED)
        return errno;

    struct memory_file *mf_ptr = data;
    memset(mf_ptr, 0, sizeof(*mf_ptr));

#ifndef MEMFILE_NO_MUTEX
    if ((flags & MF_OPEN_NOLOCK) == 0)
    {
        mf_ptr->has_mutex = true;

        int mutex_ret = pthread_mutex_init(&mf_ptr->mtx, NULL);

        if (mutex_ret != 0)
        {
            munmap(data, requested_size);

            return mutex_ret;
        }
    }
#endif

    struct memory_file_region *firstRegion = (struct memory_file_region *) (((uint8_t*) data) + control_block_size);

    memset(firstRegion, 0, sizeof(*firstRegion));
    firstRegion->prev = firstRegion;
    firstRegion->next = firstRegion;
    firstRegion->ptr = ((uint8_t *) data) + header_size + control_block_size;
    firstRegion->length = requested_size - header_size - control_block_size;
    firstRegion->mf = mf_ptr;

    mf_ptr->total_size = requested_size;
    mf_ptr->free = firstRegion->length;
    mf_ptr->data = data;
    mf_ptr->regions = firstRegion;

    *mf = mf_ptr;
    return 0;
}

int mf_open_path(struct memory_file **mf, const char * path, size_t requested_size, int flags)
{
    int fd = open(path, O_CLOEXEC | O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

    if (fd == -1)
        return errno;

    int ret = ftruncate64(fd, (off64_t) requested_size);

    if (ret != 0)
    {
        close(fd);
        return errno;
    }

    ret = mf_open_fd(mf, fd, requested_size, flags);

    close(fd);

    return ret;
}

int mf_close(struct memory_file **mf)
{
    int ret = 0;

#ifndef MEMFILE_NO_MUTEX
    if ((*mf)->has_mutex)
        ret = pthread_mutex_destroy(&(*mf)->mtx);
#endif

    if (ret == 0 && (*mf)->data)
        ret = munmap((*mf)->data, (*mf)->total_size) == 0 ? 0 : errno;

    if (ret == 0)
        *mf = NULL;

    return ret;
}

void *mf_alloc(struct memory_file *mf, size_t size, int flags)
{
    if (!mf->data)
        return NULL;

#ifndef MEMFILE_NO_MUTEX
    if (0 != mf_lock(mf))
        return NULL;
#endif

    struct memory_file_region* to_use = mf->allocate_next;

    if (to_use == NULL)
        to_use = mf->regions;

    struct memory_file_region* first_seen = to_use;
    uint8_t break_if_first_seen_matches = 0;

    size_t required_size = mf_align_size(size);
    size_t header_size = mf_align_size(sizeof(struct memory_file_region));
    size_t required_size_with_hdr = required_size + header_size;

    void *allocated = NULL;

    do
    {
        // We looped around. Nothing found.
        if (break_if_first_seen_matches && first_seen == to_use)
            break;

        if (to_use->used || (to_use->length < required_size_with_hdr && to_use->length != required_size))
        {
            to_use = to_use->next;
            break_if_first_seen_matches = 1;
            continue;
        }

        // We found one!
        to_use->used = 1;
        to_use->zero_on_free = (flags & MF_ALLOC_ZERO_ON_FREE) ? 1 : 0;

        void *ptr = to_use->ptr;
        mf->allocate_next = to_use;
        mf->regions_allocated++;
        mf->free -= required_size;

        if (to_use->length != required_size)
        {
            struct memory_file_region *new_header = (struct memory_file_region *) ((uint8_t *) to_use->ptr + required_size);
            memset(new_header, 0, sizeof(struct memory_file_region));
            new_header->ptr = (uint8_t *) new_header + header_size;
            new_header->length = to_use->length - required_size - header_size;
            new_header->mf = mf;

            to_use->length = required_size;

            new_header->next = to_use->next;
            to_use->next = new_header;

            new_header->prev = to_use;
            new_header->next->prev = new_header;

            mf->allocate_next = new_header;
            mf->free -= header_size;
        }

        allocated = ptr;
        break;
    }
    while (1);

    mf_unlock(mf);

    return allocated;
}

static inline struct memory_file_region * mf_merge_previous_regions(struct memory_file_region *region)
{
    size_t header_length = mf_align_size(sizeof(struct memory_file_region));

    do
    {
        struct memory_file_region *prev = region->prev;

        // Also check whether we are the first block in the whole memory mapping (prev > region)
        if (prev == region || prev->used || prev > region)
            return region;

        // We can merge!
        prev->length += region->length + header_length;
        prev->next = region->next;
        region->next->prev = prev;

        region->mf->free += header_length;

        if (region->mf->allocate_next == region)
            region->mf->allocate_next = prev;

        region = prev;
    }
    while (1);
}

static inline void mf_merge_next_regions(struct memory_file_region *region)
{
    size_t header_length = mf_align_size(sizeof(struct memory_file_region));

    do
    {
        struct memory_file_region *next = region->next;

        // Also check whether we are the first block in the whole memory mapping (prev > region)
        if (next == region || next->used || next < region)
            return;

        // We can merge!
        region->length += next->length + header_length;
        region->next = next->next;
        next->next->prev = region;

        region->mf->free += header_length;
    }
    while (1);
}

int mf_free(void *ptr)
{
    if (ptr == NULL)
        return 0;

    struct memory_file_region *region = (struct memory_file_region *) ((uint8_t *) ptr - mf_align_size(sizeof(struct memory_file_region)));
    assert(region->used);

    int ret = mf_lock(region->mf);

    if (ret != 0)
        return ret;

    region->used = 0;
    region->mf->regions_allocated--;
    region->mf->free += region->length;

    if (region->zero_on_free)
    {
        region->zero_on_free = 0;
        memset(region->ptr, 0, region->length);
    }

    region = mf_merge_previous_regions(region);
    mf_merge_next_regions(region);

    mf_unlock(region->mf);

    return 0;
}

ssize_t mf_get_free(struct memory_file *mf)
{
    int lock_ret = mf_lock(mf);

    if (lock_ret != 0)
        return -lock_ret;

    size_t ret = mf->free;

    mf_unlock(mf);

    return (ssize_t) ret;
}

ssize_t mf_get_allocations(struct memory_file *mf)
{
    int lock_ret = mf_lock(mf);

    if (lock_ret != 0)
        return -lock_ret;

    size_t ret = mf->regions_allocated;

    mf_unlock(mf);

    return (ssize_t) ret;
}
