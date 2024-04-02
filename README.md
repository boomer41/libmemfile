# libmemfile

This library provides a simple interface to help using files as normal memory.
May be used to work with huge amounts of data.

The library currently is not optimized to prevent fragmentation of any kind.
Because of that, a linear search is used when the whole address space is filled up.

## Usage

**See [simple-file.c](examples/simple-file.c) for the full example.**

### Open the memory file
Open a 32 Gigabyte file by a file path:

```c
struct memory_file *mf = NULL;
int ret = mf_open_path(&mf, "./data.bin", 32ull * 1024 * 1024 * 1024, MF_OPEN_NONE);
```

You can pass several flags to the `mf_open_*` functions:

- `MF_OPEN_NONE`: No special handling.
- `MF_OPEN_NOLOCK`: Disables the internal data structure mutexes.
  The memory file **itself** is then **not** thread safe and may only be used in one thread simultaneously.
  May help speed up things. Once allocated, the allocated data regions may be used freely.

### Allocate and deallocate some memory

```c
const char *s = "Hello world!";
char *c = mf_alloc(mf, strlen(s) + 1, MF_ALLOC_NONE);

if (!c)
{
    printf("mf_alloc: failed to allocate memory\n");
    return 1;
}

strcpy(c, s);
printf("\nCopied string: (%p) %s\n\n", c, c);

mf_free(c);
```

You can pass several flags to `mf_alloc`, too:

- `MF_ALLOC_NONE`: No special handling.
- `MF_ALLOC_ZERO_ON_FREE`: The data gets zeroed out automatically by a `memset`-call on deallocation.

### Close the memory file

```c
mf_close(&mf);
```

## CMake Submodule Support

This library can be included as a CMake submodule.
When it detects that circumstance, most of the boilerplate targets get disabled and you end up with the library target only.

For a list of configuration options, see root [CMakeLists.txt](CMakeLists.txt)

## pkgconfig

The library uses `pkgconfig` for discovery in other projects.
To use, simply query `pkgconfig` for `libmemfile`:

```bash
gcc simple-file.c $(pkg-config --cflags --libs libmemfile)
```

## Licensing

Copyright 2024 Stephan Brunner

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
