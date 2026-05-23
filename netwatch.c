#define INITGUID 
#include <winsock2.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <string.h>
#include <stdio.h>

#define MAX_EVENTS 2

TRACEHANDLE sessionHandle = 0;// Trace session handler
TRACEHANDLE traceHandle = 0; 

typedef char IPv4[20];
typedef struct {
    DWORD PID;
    IPv4 source_ip;
    USHORT source_port;
    IPv4 dest_ip;
    USHORT dest_port;
} NetEvent;

int SupportedEvents[MAX_EVENTS] = {
    12,
    13
};

// Callback function called by ETW at each event from provider
VOID WINAPI Callback(PEVENT_RECORD record){
    UCHAR event_opcode = record->EventHeader.EventDescriptor.Opcode; // Similar to an event ID
    int suported = 0;
    // Checks if the event Opcode is supported
    for (int c = 0; c<MAX_EVENTS; c++){
        if (SupportedEvents[c] == event_opcode){
            suported = 1;
            break;
        }
    }
    if (!suported) return;
    // Getting metadata about the event
    DWORD size = 0;
    TdhGetEventInformation(// Fails and saves the size of PTRACE_EVENT_INFO inside "size"
        record,
        0,
        NULL,
        NULL,
        &size
    );
    PTRACE_EVENT_INFO event_metadata = (PTRACE_EVENT_INFO)malloc(size);
    DWORD status = TdhGetEventInformation(
        record,
        0,
        NULL,
        event_metadata,
        &size
    );
    if (status != ERROR_SUCCESS){
        free(event_metadata);
        perror("[-] Error ");
        return;
    }

    // Getting the actual data about the event
    NetEvent event;
    ZeroMemory(&event, sizeof(event));
    for (ULONG c = 0; c < event_metadata->TopLevelPropertyCount; c++){ // Iterates over the event_metadata properties
        EVENT_PROPERTY_INFO * property_info = &event_metadata->EventPropertyInfoArray[c];
        PWSTR property_name = (PWSTR)((PBYTE)event_metadata + property_info->NameOffset);
        
        PROPERTY_DATA_DESCRIPTOR desc;
        ZeroMemory(&desc, sizeof(desc));
        desc.PropertyName = (ULONGLONG)property_name;
        desc.ArrayIndex = ULONG_MAX;
        DWORD datasize = 0;
        TdhGetPropertySize(
            record,
            0,
            NULL,
            1,
            &desc,
            &datasize
        );
        BYTE * buffer = (BYTE*)malloc(datasize);
        status = TdhGetProperty(
            record,
            0,
            NULL,
            1,
            &desc,
            datasize,
            buffer
        );
        USHORT inType = property_info->nonStructType.InType;
        USHORT outType = property_info->nonStructType.OutType;
        // Filling the NetEvent struct for readability
        switch (inType)
        {
        case 8: //UINT32
            if (wcscmp(L"daddr", property_name) == 0){// IPv4
                DWORD ip = *(DWORD*)buffer;
                BYTE * b = (BYTE*)&ip;
                sprintf(event.dest_ip, "%u.%u.%u.%u\0", b[0], b[1], b[2], b[3]);
            }else if (wcscmp(L"saddr", property_name) == 0){
                DWORD ip = *(DWORD*)buffer;
                BYTE * b = (BYTE*)&ip;
                sprintf(event.source_ip, "%u.%u.%u.%u\0", b[0], b[1], b[2], b[3]);
            }else if (wcscmp(L"PID", property_name) == 0) event.PID = *(DWORD*)buffer;
            break;
        case 6: //UINT16
            if (wcscmp(L"sport", property_name) == 0) event.source_port = ntohs(*(USHORT*)buffer);
            else if (wcscmp(L"dport", property_name) == 0) event.dest_port = ntohs(*(USHORT*)buffer);
            break;
        default:
            break;
        }
        free(buffer);
    }   

    // Converts timestamp to local time
    FILETIME filetime;
    FileTimeToLocalFileTime((FILETIME *)(&record->EventHeader.TimeStamp), &filetime);
    SYSTEMTIME systemtime;
    FileTimeToSystemTime(&filetime, &systemtime);

    // Output event information
    printf("[+] New Event at %hu/%hu/%hu at %hu:%hu | PID: %lu\n", systemtime.wDay, systemtime.wMonth, systemtime.wYear, systemtime.wHour, systemtime.wMinute, event.PID);
    PWSTR eventName = (PWSTR)((PBYTE)event_metadata + event_metadata->OpcodeNameOffset);
    wprintf(L"   * Event Type: %ls\n", eventName);
    wprintf(L"   * Source Address: %s:%hu\n", event.source_ip, event.source_port);
    wprintf(L"   * Destination Address: %s:%hu\n", event.dest_ip, event.dest_port);
}

int main(){
    // Trace session configuration
    EVENT_TRACE_PROPERTIES * properties; // Pointer to the strcut thar stores the Trace Session configuration
    EVENT_TRACE_LOGFILE logfile;

    ULONG buffersize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME);
    
    properties = (EVENT_TRACE_PROPERTIES*)calloc(1, buffersize); //all zeros allocated
    properties->Wnode.BufferSize = buffersize;
    properties->Wnode.Guid = SystemTraceControlGuid;
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->EnableFlags = EVENT_TRACE_FLAG_NETWORK_TCPIP;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    
    // Not necessary, KERNEL_LOGGER is open by default
    /*ULONG trace_status = StartTrace(
        &sessionHandle,
        KERNEL_LOGGER_NAME,
        properties
    );
    if (trace_status) wprintf(L"[-] Trace Status: %lu\n", trace_status);*/
    
    // Opens trace for consuming and defines callback function
    ZeroMemory(&logfile, sizeof(EVENT_TRACE_LOGFILE));
    logfile.LoggerName = KERNEL_LOGGER_NAME;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = Callback;
    traceHandle = OpenTrace(&logfile);
    ProcessTrace(&traceHandle, 1, NULL, NULL);

    return 0;
}

