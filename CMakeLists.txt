cmake_minimum_required(VERSION 3.15)
#enable_language(CSharp)
enable_language(CXX)
enable_language(C)

#set(CMAKE_CSharp_FLAGS "/define:TRACE /langversion:7.3")

#set(staticLinkToMyDll TRUE)
set(staticLinkToMyDll FALSE)


project(test_dll_load)

add_definitions(-DUNICODE -D_UNICODE)
set(CMAKE_CXX_STANDARD 20)
#set(CMAKE_CXX_STANDARD 17)

#---------------------------------------------------------------------
add_executable(test_dll_load 
    minhook/src/buffer.c
    minhook/src/hook.c
    minhook/src/trampoline.c
    minhook/src/hde/hde64.c
    minhook/src/hde/hde32.c

    minhook/src/buffer.h
    minhook/src/hde/hde32.h
    minhook/src/hde/hde64.h
    minhook/include/MinHook.h
    minhook/src/hde/pstdint.h
    minhook/src/hde/table32.h
    minhook/src/hde/table64.h
    minhook/src/trampoline.h
    minhook/LICENSE.txt
    test_dll.cpp
    ntddk.h
)

set(outDir ${CMAKE_CURRENT_SOURCE_DIR}/bin)

set_target_properties( test_dll_load
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${outDir}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${outDir}"
)

add_dependencies(test_dll_load inject_exe)

#add_custom_command( TARGET test_dll_load POST_BUILD COMMAND dotnet run --project ${CMAKE_CURRENT_SOURCE_DIR}/inject_exe/inject_exe.csproj )
#---------------------------------------------------------------------

#add_executable(inject_exe inject_exe.cpp) 

#set_target_properties( inject_exe
#    PROPERTIES
#    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${outDir}"
#    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${outDir}"
#)

#---------------------------------------------------------------------

add_library(dllstub SHARED dllstub.cpp)

set_target_properties( dllstub
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${outDir}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${outDir}"
)

#---------------------------------------------------------------------
add_library(mydll SHARED dll.cpp)

set_target_properties( mydll
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${outDir}/ext"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${outDir}/ext"
)

#---------------------------------------------------------------------
add_library(mydll2 SHARED dll.cpp)

set_target_properties( mydll2
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${outDir}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${outDir}"
)


include_external_msproject(inject_exe ${CMAKE_CURRENT_SOURCE_DIR}/inject_exe/inject_exe.csproj PLATFORM AnyCPU)


#set_target_properties(mydll PROPERTIES VS_GLOBAL_CLRSupport "true")
#target_compile_options(mydll PRIVATE /clr:netcore)
#set_property(TARGET mydll PROPERTY DOTNET_TARGET_FRAMEWORK "netcoreapp3.1")
target_include_directories(test_dll_load PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(${staticLinkToMyDll})
    target_link_libraries(test_dll_load ${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/mydll.lib)
    add_dependencies(test_dll_load mydll)
    add_compile_definitions(test_dll_load STATIC_LINK_TO_DLL)
endif()



#target_link_libraries(test_dll_load delayimp.lib)
set_target_properties(test_dll_load PROPERTIES LINK_FLAGS "/DELAYLOAD:mydll.dll")


