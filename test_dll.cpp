#include "minhook/include/MinHook.h"
#include <stdio.h>
#include <windows.h>
#include <filesystem>
#include <map>
#include <iostream>
#include <fstream>
#include <KtmW32.h>
#ifdef PECONV
	#include <peconv.h>
#endif
using namespace std;
using namespace std::filesystem;
//#define _NTDLL_SELF_
#include "ntddk.h"

extern "C" __declspec(dllimport) void HelloDll2();

HANDLE g_hMapFile;
bool g_tryMemoryMapping = false;
//bool g_tryMemoryMapping = true;
bool g_TransactionFile = true;
HANDLE g_hTransationFile;
string g_dllFile;

const wchar_t* memoryMapingName = L"Global\\MyFileMappingObject";
const wchar_t* memoryMapingNameKernel = L"\\BaseNamedObjects\\MyFileMappingObject";
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
wstring redirectToFile;
wstring baseDir;
HANDLE g_dllsContainer = 0;
bool g_bDllLoadRedirect = false;
bool g_bDllManualLoad = false;
bool g_bDumpDllContent= false;
map<HANDLE, int> g_handleToOffset;
map<HANDLE, int> g_sectionToOffset;

using NtOpenFile_pfunc = NTSTATUS (WINAPI*)
	( PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, 
	  PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions );

NtOpenFile_pfunc NtOpenFile_origfunc;

using NtDuplicateObject_pfunc = NTSTATUS(NTAPI*)
(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);

NtDuplicateObject_pfunc NtDuplicateObject_origfunc;


NTSTATUS WINAPI NtOpenFile_detour(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, 
	PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
{
	POBJECT_ATTRIBUTES poattr = ObjectAttributes;
	wstring_view name(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length / sizeof(wchar_t));
	bool redirectOpen = name._Starts_with(redirectFromDir);
	NTSTATUS r = 0;

	if(g_tryMemoryMapping && redirectOpen)
	{
		*FileHandle = g_hMapFile;
		return 0;
	}

	if (g_TransactionFile && redirectOpen)
	{
		//r = NtDuplicateObject_origfunc(GetCurrentProcess(), g_hTransationFile, GetCurrentProcess(), FileHandle, DesiredAccess, 0,0);
		//*FileHandle = g_hTransationFile;

		DWORD options, isolationLvl, isolationFlags, timeout;
		options = isolationLvl = isolationFlags = timeout = 0;

		HANDLE hTransaction = CreateTransaction(nullptr, nullptr, options, isolationLvl, isolationFlags, timeout, nullptr);
		g_hTransationFile = CreateFileTransactedW(
			L"mydll_x1.dll",
			GENERIC_WRITE | GENERIC_READ,
			0,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL,
			hTransaction,
			NULL,
			NULL
		);

		DWORD writtenLen = 0;
		WriteFile(g_hTransationFile, &g_dllFile[0], g_dllFile.size(), &writtenLen, NULL);
		FlushFileBuffers(g_hTransationFile);
		SetFilePointer(g_hTransationFile, 0, 0, FILE_BEGIN);

		*FileHandle = g_hTransationFile;
		return r;
	}
	

	r = NtOpenFile_origfunc(FileHandle, DesiredAccess, poattr, IoStatusBlock, ShareAccess, OpenOptions);
	if(SUCCEEDED(r) && g_bDllLoadRedirect)
	{
		if(redirectOpen && g_dllsContainer == 0)
		{
			OBJECT_ATTRIBUTES oattr;
			UNICODE_STRING ustr;

			if (redirectOpen)
			{
				oattr = *ObjectAttributes;
				oattr.ObjectName = &ustr;
				//RtlInitUnicodeString(&ustr, redirectTo.c_str());
				RtlInitUnicodeString(&ustr, memoryMapingNameKernel);
				poattr = &oattr;
			}

			if(g_tryMemoryMapping && redirectOpen)
			{
				r = NtOpenSection(FileHandle, SECTION_MAP_READ | SECTION_MAP_WRITE, &oattr);
			}
			else
			{
				r = NtOpenFile_origfunc(&g_dllsContainer, DesiredAccess, poattr, IoStatusBlock, ShareAccess, OpenOptions);
			}

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

NTSTATUS NTAPI NtDuplicateObject_detour(HANDLE SourceProcessHandle, HANDLE SourceHandle, 
	HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
{
	return NtDuplicateObject_origfunc(SourceProcessHandle, SourceHandle,TargetProcessHandle, 
		TargetHandle, DesiredAccess, HandleAttributes, Options);
}

using NtMapViewOfSection_pfunc = NTSTATUS(NTAPI*)
(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect);

NtMapViewOfSection_pfunc NtMapViewOfSection_origfunc;

//-------------------------------------------------------------------------------------------------------------
using NtCreateSection_pfunc = NTSTATUS (NTAPI*)
	( PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle );

NtCreateSection_pfunc NtCreateSection_origfunc;

NTSTATUS NTAPI NtCreateSection_detour(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
{
	HANDLE h = 0;
	ifstream is;
	LARGE_INTEGER fileSize;
	SIZE_T fileSize2;
	SIZE_T memSize;
	if(FileHandle)
	{
		h = FileHandle;
	}

	bool trackSectionOpen = g_handleToOffset.contains(h) || g_bDllManualLoad;
	if(trackSectionOpen && g_bDllManualLoad)
	{
		FileHandle = nullptr;
		is.open(redirectToFile.c_str(), ios::binary);
		// get length of file:
		is.seekg(0, ios::end);
		fileSize2 = is.tellg();

		memSize = fileSize2;
		//memSize += 0x1000 - (memSize % 0x1000);
		//memSize += 0x10000 - (memSize % 0x10000);

		fileSize.QuadPart = memSize;

		MaximumSize = &fileSize;
		is.seekg(0, ios::beg);
	}

	NTSTATUS r;

	if(g_bDllManualLoad)
	{
		// Use same techinique as PeLoader.cpp, mapped_loader, only in here.
		r = NtCreateSection_origfunc(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, FileHandle);
	}
	else
	{
		if(g_bDumpDllContent)
		{
			r = NtCreateSection_origfunc(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, PAGE_EXECUTE_READ, SEC_COMMIT, FileHandle);

		}
		else
		{
			if(g_TransactionFile)
			{
				//r = NtCreateSection_origfunc(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
				//r = NtCreateSection_origfunc(SectionHandle, SECTION_ALL_ACCESS, ObjectAttributes, MaximumSize, PAGE_EXECUTE_READ, SEC_IMAGE, FileHandle);
				//r = NtCreateSection_origfunc(SectionHandle, SECTION_ALL_ACCESS, ObjectAttributes, MaximumSize, PAGE_READONLY, SEC_IMAGE, FileHandle);
				r = NtCreateSection_origfunc(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, PAGE_READONLY, AllocationAttributes, FileHandle);
				//r = NtCreateSection_origfunc(SectionHandle,
				//	SECTION_ALL_ACCESS,
				//	NULL,
				//	0,
				//	PAGE_READONLY,
				//	SEC_IMAGE,
				//	g_hTransationFile
				//);
 			}
			else
			{
				r = NtCreateSection_origfunc(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
			}
		}
	}

	if(SUCCEEDED(r) && trackSectionOpen )
	{
		if(g_bDllLoadRedirect)
		{
			g_sectionToOffset[*SectionHandle] = g_handleToOffset[h];
		}
		
		if(g_bDllManualLoad)
		{
			PVOID mapSectionAddress = NULL;
			r = NtMapViewOfSection_origfunc(
				*SectionHandle,
				NtCurrentProcess(),
				&mapSectionAddress,
				NULL, NULL, NULL,
				&memSize,
				ViewUnmap,
				NULL,
				PAGE_EXECUTE_READWRITE
			);
			if (SUCCEEDED(r))
			{
				memset(mapSectionAddress, 0, memSize);
				is.read((char*)mapSectionAddress, fileSize2);

				DWORD oldProtect = 0;
				VirtualProtect(mapSectionAddress, memSize, PAGE_READWRITE, &oldProtect);

#ifdef PECONV
				bool b = peconv::relocate_module((BYTE*)mapSectionAddress, fileSize2, (ULONGLONG)mapSectionAddress);
				if(!b)
				{
					r = 0xC0000001;
				}
#endif
				//NtUnmapViewOfSection(NtCurrentProcess(), mapSectionAddress);
			}
		}
	}

	if (SUCCEEDED(r) && g_bDumpDllContent)
	{
		PVOID mapSectionAddress = NULL;
		memSize = 0;
		//memSize = 34304;
		//memSize = 34304 + (34304 - (34304) % 0x1000);
		r = NtMapViewOfSection_origfunc(
			*SectionHandle,
			NtCurrentProcess(),
			&mapSectionAddress,
			NULL, NULL, NULL,
			&memSize,
			//ViewUnmap,
			ViewShare,
			NULL,
			//PAGE_READONLY
			PAGE_READWRITE
		);

		if (SUCCEEDED(r))
		{
			FILE* ptr = _wfopen((baseDir + L"\\dll1.dump").c_str(), L"wb");
			fwrite(mapSectionAddress, 1, 34304, ptr);
			fclose(ptr);
		}
	}

	if (trackSectionOpen && g_bDllManualLoad)
	{
		is.close();
	}

	return r;
}

//-------------------------------------------------------------------------------------------------------------

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
	if (SUCCEEDED(r) && g_bDumpDllContent)
	{
		FILE* ptr = _wfopen((baseDir + L"\\dll2.dump").c_str(), L"wb");
		fwrite(*BaseAddress, 1, 34304, ptr);
		fclose(ptr);
	}

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
using NtDeviceIoControlFile_pfunc = NTSTATUS(NTAPI*)
(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
	ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength );

NtDeviceIoControlFile_pfunc NtDeviceIoControlFile_origfunc;

NTSTATUS NTAPI NtDeviceIoControlFile_detour(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
	ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)
{
	return NtDeviceIoControlFile_origfunc(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
		IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}



//-------------------------------------------------------------------------------------------------------------


int wmain(int argc, wchar_t** argv)
{
	printf("before HelloDll\n");

#ifdef STATIC_LINK_TO_DLL
	HelloDll2();
	printf("take 2\n");
	return 0;
#endif

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
	redirectToFile = weakly_canonical(path(argv[0])).parent_path().wstring() + L"\\ext\\mydll.dll";
	baseDir = weakly_canonical(path(argv[0])).parent_path().wstring();

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
	r = MH_CreateHookApi(ntdll_dll, "NtDeviceIoControlFile", &NtDeviceIoControlFile_detour, (LPVOID*)&NtDeviceIoControlFile_origfunc);
	
	if(g_tryMemoryMapping || g_TransactionFile)
	{
		ifstream is;
		is.open(extdll, ios::binary);
		// get length of file:
		is.seekg(0, ios::end);
		fileSize = is.tellg();
		is.seekg(0, ios::beg);
		char* pfile;

		if(g_tryMemoryMapping)
		{
			//HANDLE hMapFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, fileSize, memoryMapingName);
			//g_hMapFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, SEC_IMAGE | PAGE_READONLY, 0, fileSize, nullptr);
			//g_hMapFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READONLY, 0, fileSize, nullptr);
			//g_hMapFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, SEC_COMMIT|PAGE_READWRITE, 0, fileSize, nullptr);
			//g_hMapFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, fileSize, nullptr);
			g_hMapFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, SEC_IMAGE_NO_EXECUTE, 0, fileSize, nullptr);
			auto lastErr = GetLastError();
			if (g_hMapFile == 0)
			{
				printf("- Requires elevated mode");
				return 2;
			}
			char* pfile = (char*)MapViewOfFile(g_hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, fileSize);
			//char* pfile = (char*)MapViewOfFile(g_hMapFile, FILE_MAP_READ, 0, 0, fileSize);
			DWORD oldProtect = 0;
			VirtualProtect(pfile, fileSize, PAGE_EXECUTE_READ, &oldProtect);

			is.read(pfile, fileSize);
		}

		if(g_TransactionFile)
		{
			g_dllFile.resize(fileSize);
			is.read(&g_dllFile[0], fileSize);


			//DWORD options, isolationLvl, isolationFlags, timeout;
			//options = isolationLvl = isolationFlags = timeout = 0;

			//HANDLE hTransaction = CreateTransaction(nullptr, nullptr, options, isolationLvl, isolationFlags, timeout, nullptr);
			//g_hTransationFile = CreateFileTransactedW(
			//	L"mydll_x1.dll",
			//	GENERIC_WRITE | GENERIC_READ,
			//	0,
			//	NULL,
			//	CREATE_ALWAYS,
			//	FILE_ATTRIBUTE_NORMAL,
			//	NULL,
			//	hTransaction,
			//	NULL,
			//	NULL
			//);

			//DWORD writtenLen = 0;
			//WriteFile(g_hTransationFile, &g_dllFile[0], fileSize, &writtenLen, NULL);
			//FlushFileBuffers(g_hTransationFile);
			//SetFilePointer(g_hTransationFile, 0, 0, FILE_BEGIN);

			//HANDLE hSection = nullptr;
			//NTSTATUS status = NtCreateSection(&hSection,
			//	SECTION_ALL_ACCESS,
			//	NULL,
			//	0,
			//	PAGE_READONLY,
			//	SEC_IMAGE,
			//	g_hTransationFile
			//);
		}

		is.close();

	}


	MH_EnableHook(MH_ALL_HOOKS);
	//LoadLibrary(dll.wstring().c_str());
	//HMODULE hdll = LoadLibrary(exe.c_str());
	HMODULE hdll = LoadLibrary(dll.c_str());
	//HMODULE hdll = LoadLibraryEx(exe.c_str(), NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
	//HMODULE hdll = LoadLibraryEx(exe.c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE);
	auto lastErr = GetLastError();
	//HMODULE hexe = LoadLibrary(redirectTo.c_str());

	FARPROC p1 = GetProcAddress(hdll, "HelloDll");
	FARPROC p2 = GetProcAddress(hdll, "HelloDll2");
	//p();

	p2();

	FreeLibrary(hdll);

	//HelloDll();
	printf("after HelloDll\n");
	return 0;
}

