# Net-Watch
## Presentation
A process-aware network monitor for single hosts. 
The project's main detection goals are:
* Connections involving suspicious executables (Ex: LOLBins)
* C2 Beaconing
* Network Scanning
----
## Installing
### Windows
#### Download dependencies
```
git clone https://github.com/Atreus75/Net-Watch.git
cd Net-Watch
wget https://raw.githubusercontent.com/DaveGamble/cJSON/master/cJSON.c
wget https://raw.githubusercontent.com/DaveGamble/cJSON/master/cJSON.h
```
#### Compiling
**GCC MinGW**: 
```
gcc -O2 win_event_collect.c cJSON.c -o netwatch -ladvapi32 -ltdh -lws2_32
```
**MSVC**:
```
cl win_event_collect.c cJSON.c /Fe:netwatch.exe /link advapi32.lib tdh.lib ws2_32.lib
```
#### Running
`.\netwatch.exe`
