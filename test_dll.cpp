#include "minhook/include/MinHook.h"
#include <stdio.h>
#include <windows.h>
#include <filesystem>
#include <map>
#include <iostream>
#include <fstream>
using namespace std;
using namespace std::filesystem;
//#define _NTDLL_SELF_
#include "ntddk.h"

extern "C" __declspec(dllimport) void HelloDll();

const wchar_t* memoryMapingName = L"MyFileMappingObject";
const wchar_t* memoryMapingNameKernel = L"\\??\\MyFileMappingObject";
int fileSize = 52224;

//-------------------------------------------------------------------------------------------------------------
using OpenFileW_pfunc = HFILE(WINAPI*)(LPWSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle );
OpenFileW_pfunc  OpenFileorigfunc;

HFILE WINAPI OpenFile_detour(LPWSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle)
{
	return OpenFileorigfunc(lpFileName, lpReOpenBuff, uStyle);
}

//-------------------------------------------------------------------------------------------------------------
using FindFirstFileW_pfunc = HANDLE(WINAPI*)(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
FindFirstFileW_pfunc  FindFirstFileW_origfunc;

HANDLE WINAPI FindFirstFileW_detour(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData)
{
	return FindFirstFileW_origfunc(lpFileName, lpFindFileData);
}

//-------------------------------------------------------------------------------------------------------------

using LdrLoadDll_pfunc = NTSTATUS(WINAPI*)(PWSTR SearchPath, PULONG DllCharacteristics, UNICODE_STRING* DllName, PVOID* BaseAddress);
LdrLoadDll_pfunc LdrLoadDll_origfunc;

NTSTATUS WINAPI LdrLoadDll_detour(PWSTR SearchPath, PULONG DllCharacteristics, UNICODE_STRING* DllName, PVOID* BaseAddress)
{
	//ULONG DllCharacteristics2 = IMAGE_FILE_DLL;
	
	return LdrLoadDll_origfunc(SearchPath, DllCharacteristics, DllName, BaseAddress);
}

//-------------------------------------------------------------------------------------------------------------

wstring exePath;
wstring redirectFromDir;
wstring redirectTo;
HANDLE g_dllsContainer = 0;
map<HANDLE, int> g_handleToOffset;
map<HANDLE, int> g_sectionToOffset;

using NtOpenFile_pfunc = NTSTATUS (WINAPI*)
	( PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, 
	  PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions );

NtOpenFile_pfunc NtOpenFile_origfunc;

NTSTATUS WINAPI NtOpenFile_detour(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, 
	PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
{
	POBJECT_ATTRIBUTES poattr = ObjectAttributes;
	wstring_view name(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length / sizeof(wchar_t));
	bool redirectOpen = name._Starts_with(redirectFromDir);

	NTSTATUS r = NtOpenFile_origfunc(FileHandle, DesiredAccess, poattr, IoStatusBlock, ShareAccess, OpenOptions);
	if(SUCCEEDED(r))
	{
		if(redirectOpen && g_dllsContainer == 0)
		{
			OBJECT_ATTRIBUTES oattr;
			UNICODE_STRING ustr;

			if (redirectOpen)
			{
				oattr = *ObjectAttributes;
				oattr.ObjectName = &ustr;
				RtlInitUnicodeString(&ustr, redirectTo.c_str());
				//RtlInitUnicodeString(&ustr, memoryMapingNameKernel);
				poattr = &oattr;
			}
			NTSTATUS r2 = NtOpenFile_origfunc(&g_dllsContainer, DesiredAccess, poattr, IoStatusBlock, ShareAccess, OpenOptions);

			// Ingnore return value
			if (!SUCCEEDED(r))
			{
				g_dllsContainer = 0;
			}
		}

		if(g_dllsContainer)
		{
			g_handleToOffset[*FileHandle] = 0x50000;
			//g_handleToOffset[*FileHandle] = 0x10000;
		}
	}

	return r;
}

//-------------------------------------------------------------------------------------------------------------
using NtClose_pfunc = NTSTATUS (NTAPI*) (HANDLE Handle);

NtClose_pfunc NtClose_origfunc;

NTSTATUS NTAPI NtClose_detour(HANDLE Handle)
{
	auto r = NtClose_origfunc(Handle);
	return r;
}

//-------------------------------------------------------------------------------------------------------------
using NtDuplicateObject_pfunc = NTSTATUS (NTAPI*)
	(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, 
	 ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options );

NtDuplicateObject_pfunc NtDuplicateObject_origfunc;

NTSTATUS NTAPI NtDuplicateObject_detour(HANDLE SourceProcessHandle, HANDLE SourceHandle, 
	HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
{
	return NtDuplicateObject_origfunc(SourceProcessHandle, SourceHandle,TargetProcessHandle, 
		TargetHandle, DesiredAccess, HandleAttributes, Options);
}


//-------------------------------------------------------------------------------------------------------------
using NtCreateSection_pfunc = NTSTATUS (NTAPI*)
	( PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle );

NtCreateSection_pfunc NtCreateSection_origfunc;

NTSTATUS NTAPI NtCreateSection_detour(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
{
	HANDLE h = 0;
	if(FileHandle)
	{
		h = FileHandle;
	}

	bool trackSectionOpen = g_handleToOffset.contains(h);
	if(trackSectionOpen)
	{
		FileHandle = g_dllsContainer;
	}

	auto r = NtCreateSection_origfunc(SectionHandle, DesiredAccess, ObjectAttributes,
		MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);

	if(SUCCEEDED(r) && trackSectionOpen)
	{
		g_sectionToOffset[*SectionHandle] = g_handleToOffset[h];
	}

	return r;
}

//-------------------------------------------------------------------------------------------------------------
using NtMapViewOfSection_pfunc = NTSTATUS (NTAPI*)
	( HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
	  PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect );

NtMapViewOfSection_pfunc NtMapViewOfSection_origfunc;

NTSTATUS NTAPI NtMapViewOfSection_detour(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, 
	SIZE_T ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, 
	ULONG AllocationType, ULONG Protect)
{
	LARGE_INTEGER localSectionOffset;
	SIZE_T localViewSize;
	bool traceSection = g_sectionToOffset.contains(SectionHandle);

	if (g_sectionToOffset.contains(SectionHandle))
	{
		localSectionOffset.QuadPart = g_sectionToOffset[SectionHandle];
		if(SectionOffset != nullptr)
		{
			localSectionOffset.QuadPart += SectionOffset->QuadPart;
		}
		SectionOffset = &localSectionOffset;
		//ViewSize = &localViewSize;
		//localViewSize = 0x12000;
		//localViewSize = 0xC00;
	}

	auto r = NtMapViewOfSection_origfunc(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize,
		InheritDisposition, AllocationType, Protect);

	//if(SUCCEEDED(r) && traceSection)
	//{
	//	void* addr = *BaseAddress;
	//	addr = ((char*)addr + g_sectionToOffset[SectionHandle]);
	//	*BaseAddress = addr;
	//}
	
	return r;
}

//-------------------------------------------------------------------------------------------------------------
using NtReadFile_pfunc = NTSTATUS (NTAPI*)
	(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
	 PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key );

NtReadFile_pfunc NtReadFile_origfunc;

NTSTATUS NTAPI NtReadFile_detour(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
	PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
	return NtReadFile_origfunc(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}


//-------------------------------------------------------------------------------------------------------------


int wmain(int argc, wchar_t** argv)
{
	printf("before HelloDll\n");
	MH_STATUS r = MH_Initialize();
	if (r != MH_OK)
	{
		printf("MH_Initialize failed\n");
		return 0;
	}
	const wchar_t* kernel32_dll = L"kernel32.dll";
	const wchar_t* ntdll_dll = L"ntdll.dll";
	HMODULE h = GetModuleHandleW(kernel32_dll);
	void* oldOpenFile = (void*)GetProcAddress(h, "OpenFileW");

	//auto dll = weakly_canonical(path(argv[0])).parent_path().append("mydll.dll");
	auto dll = weakly_canonical(path(argv[0])).parent_path().append("dllstub.dll");
	auto extdll = weakly_canonical(path(argv[0])).parent_path().append("ext").append("mydll.dll");
	redirectFromDir = L"\\??\\" + weakly_canonical(path(argv[0])).parent_path().wstring();

	// Main executable
	redirectTo = wstring(L"\\??\\") + argv[0];
	// subfolder executable
	//redirectTo = wstring(L"\\??\\") + weakly_canonical(path(argv[0])).parent_path().wstring() + L"\\ext\\mydll.dll";

	//redirectTo = wstring(L"\\??\\") + weakly_canonical(path(argv[0])).parent_path().wstring() + L"\\mydll2.dll";

	exePath = argv[0];
	//auto exe = wstring(argv[0]) + L":1";
	//auto exe = wstring(L"\\\\.\\device\\") + wstring(argv[0]);
	//auto exe = wstring(L"\\\\.\\NUL");
	//exe.append("1.dll");

	//r = MH_CreateHookApi(kernel32_dll, "OpenFileW", &OpenFile_detour, (LPVOID*)&OpenFileorigfunc);
	//r = MH_CreateHookApi(kernel32_dll, "FindFirstFileW", &FindFirstFileW_detour, (LPVOID*)&FindFirstFileW_origfunc);
	r = MH_CreateHookApi(ntdll_dll, "LdrLoadDll", &LdrLoadDll_detour, (LPVOID*)&LdrLoadDll_origfunc);
	r = MH_CreateHookApi(ntdll_dll, "NtOpenFile", &NtOpenFile_detour, (LPVOID*)&NtOpenFile_origfunc);
	r = MH_CreateHookApi(ntdll_dll, "NtCreateSection", &NtCreateSection_detour, (LPVOID*)&NtCreateSection_origfunc);
	r = MH_CreateHookApi(ntdll_dll, "NtClose", &NtClose_detour, (LPVOID*)&NtClose_origfunc);
	r = MH_CreateHookApi(ntdll_dll, "NtDuplicateObject", &NtDuplicateObject_detour, (LPVOID*)&NtDuplicateObject_origfunc);
	r = MH_CreateHookApi(ntdll_dll, "NtMapViewOfSection", &NtMapViewOfSection_detour, (LPVOID*)&NtMapViewOfSection_origfunc);
	r = MH_CreateHookApi(ntdll_dll, "NtReadFile", &NtReadFile_detour, (LPVOID*)&NtReadFile_origfunc);
	
	//ifstream is;
	//is.open(extdll, ios::binary);
	//// get length of file:
	//is.seekg(0, ios::end);
	//fileSize = is.tellg();

	//HANDLE hMapFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, fileSize, memoryMapingName);
	//char* pfile = (char*)MapViewOfFile(hMapFile,FILE_MAP_ALL_ACCESS, 0, 0, fileSize);

	//is.seekg(0, ios::beg);
	//is.read(pfile, fileSize);
	//is.close();


	MH_EnableHook(MH_ALL_HOOKS);
	//LoadLibrary(dll.wstring().c_str());
	//HMODULE hdll = LoadLibrary(exe.c_str());
	HMODULE hdll = LoadLibrary(dll.c_str());
	//HMODULE hdll = LoadLibraryEx(exe.c_str(), NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
	//HMODULE hdll = LoadLibraryEx(exe.c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE);
	auto lastErr = GetLastError();
	//HMODULE hexe = LoadLibrary(redirectTo.c_str());

	FARPROC p = GetProcAddress(hdll, "HelloDll2");
	//p();

	//HelloDll();
	printf("after HelloDll\n");
	return 0;
}

