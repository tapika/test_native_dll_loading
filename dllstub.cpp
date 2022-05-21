#include <stdio.h>


extern "C" __declspec(dllexport) void HelloDll()
{
	printf("Hello world\r\n");
}

