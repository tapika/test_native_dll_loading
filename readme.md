## Overview

Open "Developer Command Prompt for VS 2019"
(or run command `"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\Tools\VsDevCmd.bat"`).

```
cd <project dir>
cmake . -B vsproj
cd vsproj
```

Open `test_dll_load.sln`.

Compile.

### Project contents

This git repo contains some experimenting stuff, related to native .dll loading.

### Fixing compilation bugs

If you have compilation error like this:

`6>C:\Program Files (x86)\Windows Kits\8.1\Include\um\combaseapi.h(229,21): error C2760: syntax error: unexpected token 'identifier', expected 'type specifier'`


Edit following file:
```
C:\Program Files (x86)\Windows Kits\8.1\Include\um\combaseapi.h:
...

extern "C++"
{
    template<typename T> _Post_equal_to_(pp) _Post_satisfies_(return == pp) void** IID_PPV_ARGS_Helper(T** pp) 
    {
#pragma prefast(suppress: 6269, "Tool issue with unused static_cast")
#if !_HAS_CXX20 //added line
        static_cast<IUnknown*>(*pp);    // make sure everyone derives from IUnknown
#endif //added line
        return reinterpret_cast<void**>(pp);
    }    
}
```

Add `// added line` to mentioned header file - it should fix compilation errors.


### What is this project intent ?

To provide necessary information on what I was trying to do, and what were results -
for more information see:

https://github.com/tapika/test_native_dll_loading/discussions/2


### Follow up projects

- https://github.com/tapika/dllloader - based on trials from this git repo.


