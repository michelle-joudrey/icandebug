# icandebug

## Usage
```
icandebug.exe <name of running process>
```

## Example
```
> icandebug.exe SomeMalware.exe
Detected modified functions:
0x7ffa43299600 (DbgUiConvertStateChangeStructure)
0x7ffa4326d880 (DbgBreakPoint)
0x7ffa43299560 (DbgUiConnectToDbg)
0x7ffa4326d890 (DbgUserBreakPoint)
0x7ffa432995d0 (DbgUiContinue)
0x7ffa432999b0 (DbgUiRemoteBreakin)
0x7ffa432998b0 (DbgUiDebugActiveProcess)
0x7ffa43299920 (DbgUiGetThreadDebugObject)
0x7ffa43299940 (DbgUiIssueRemoteBreakin)
0x7ffa43299a10 (DbgUiSetThreadDebugObject)
0x7ffa43299a30 (DbgUiStopDebugging)
0x7ffa43299a50 (DbgUiWaitStateChange)
0x7ffa432ab220 (DbgPrintReturnControlC)
0x7ffa432ab270 (DbgPrompt)
Press Enter to patch functions

Restoring original functions...
Success
```
