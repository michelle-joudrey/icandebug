# icandebug

## Usage
```
Usage:
  icandebug.exe -p <pid> [-h]
  icandebug.exe -n <process name> [-h]

Options:
-h    Heal modified functions
```

## Example
```
>icandebug.exe -p 1337 -h
Scanning kernelbase.dll...
Detected modified functions:
0x7ff8997d99c0 (ResumeThread)
0x7ff89978bcd0 (FreeLibrary)
0x7ff8997a2900 (LoadLibraryExW)
0x7ff8997d14c0 (LoadLibraryExA)
Healing modified functions...
Success

Scanning ntdll.dll...
Detected modified functions:
0x7ff89c8a9600 (DbgUiConvertStateChangeStructure)
0x7ff89c87d880 (DbgBreakPoint)
0x7ff89c8a9560 (DbgUiConnectToDbg)
0x7ff89c87d890 (DbgUserBreakPoint)
0x7ff89c8a95d0 (DbgUiContinue)
0x7ff89c8a99b0 (DbgUiRemoteBreakin)
0x7ff89c8a98b0 (DbgUiDebugActiveProcess)
0x7ff89c8a9920 (DbgUiGetThreadDebugObject)
0x7ff89c8a9940 (DbgUiIssueRemoteBreakin)
0x7ff89c8a9a10 (DbgUiSetThreadDebugObject)
0x7ff89c8a9a30 (DbgUiStopDebugging)
0x7ff89c8a9a50 (DbgUiWaitStateChange)
0x7ff89c8bb220 (DbgPrintReturnControlC)
0x7ff89c8bb270 (DbgPrompt)
Healing modified functions...
Success
```
