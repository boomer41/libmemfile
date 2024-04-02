#pragma once

#include <unistd.h>

#ifndef MF_BITFIELD
/**
 * Utility define to help with bitmasks.
 */
# define MF_BITFIELD(x) (1 << (x))
#endif

/**
 * No additional options given.
 */
#define MF_OPEN_NONE    0

/**
 * Disable internal locks for this specific memory file.
 * Any access or usage of the memory file is only allowed by one thread at a time.
 * The allocated data may still be used concurrently.
 */
#define MF_OPEN_NOLOCK  MF_BITFIELD(1)

/**
 * No additional options given.
 */
#define MF_ALLOC_NONE         0

/**
 * Automatically zeroes the memory out when freed.
 */
#define MF_ALLOC_ZERO_ON_FREE MF_BITFIELD(1)

/**
 * Opaque structure representing the opened memory file.
 */
struct memory_file;

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Open a memory file by a file path.
 * The file is created when it does not exist. Existing files will be overridden.
 * No locks will be placed upon the file.
 * Any data will be overridden.
 * Note that the internal data structures will be placed into the data file as well.
 * The internally opened file handle is closed when this function returns so that
 * the memory mapping is the sole reference to the opened file.
 *
 * @param mf A pointer that shall receive a pointer to the handle.
 * @param path The file path to put the data in
 * @param requested_size The requested file size in bytes.
 * @param flags A combination of MF_OPEN_*-flags.
 * @return 0 on success, an error code on failure.
 */
int mf_open_path(struct memory_file **mf, const char * path, size_t requested_size, int flags);

/**
 * Open a memory file by an existing file descriptor.
 * Any data will be overridden.
 * Note that the internal data structures will be placed into the data file as well.
 *
 * @param mf A pointer that shall receive a pointer to the handle.
 * @param fd The file descriptor to use.
 * @param requested_size The requested file size in bytes.
 * @param flags A combination of MF_OPEN_*-flags.
 * @return 0 on success, an error code on failure.
 */
int mf_open_fd(struct memory_file **mf, int fd, size_t requested_size, int flags);

/**
 * Closes a given memory file by unmapping all memory.
 *
 * @param mf The memory file. The pointer is zeroed out on success.
 * @return 0 on success, an error code on failure.
 */
int mf_close(struct memory_file **mf);

/**
 * Allocate some memory from a given memory file.
 *
 * @param mf The memory file to use.
 * @param size The requested allocation size in bytes.
 * @param flags A combination of MF_ALLOC_*-flags.
 * @return A valid pointer on success, NULL on failure.
 */
void *mf_alloc(struct memory_file *mf, size_t size, int flags);

/**
 * Free some memory returned by mf_alloc().
 *
 * @param ptr The pointer as returned by mf_alloc()
 * @return 0 on success, an error code on failure.
 */
int mf_free(void *ptr);

/**
 * Returns the number of free bytes.
 *
 * @param mf The memory file to query.
 * @return >= 0 on success, < 0 on error (error code returned).
 */
ssize_t mf_get_free(struct memory_file *mf);

/**
 * Returns the number of allocated regions.
 *
 * @param mf The memory file to query.
 * @return >= 0 on success, < 0 on error (error code returned).
 */
ssize_t mf_get_allocations(struct memory_file *mf);

#ifdef __cplusplus
}
#endif
