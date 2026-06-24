/* TO-DO:
    * 1 - Salvar eventos em um array de tamanho fixo (ou uma lista encadeada)
    * 2 - Fazer funções de comparação entre funções (sameImage, sameConnection etc)
    * 2 - Detectar beaconing utilizando a fila de eventos (Cache)
*/

#include "netwatch_lib.h"
#include <stdio.h>

// Global variables and macros
#define MAX_CACHE_SIZE 200
int EVENT_COUNTER = 0;
NetEventQueue Cache = NULL; //Global event cache for event history storing

// Windows functions
#if defined(_WIN32)
int isEventSupported(PTRACE_EVENT_INFO event_metadata){
    for (int c = 0; c<MAX_EVENTS; c++) if (wcscmp(SupportedEvents[c], (PWSTR)((PBYTE)event_metadata + event_metadata->OpcodeNameOffset)) == 0) return 1;
    return 0;
}

PTRACE_EVENT_INFO getEventMetadata(PEVENT_RECORD record){
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
        perror("[-] Error: ");
        return NULL;
    }else if (!isEventSupported(event_metadata)) return NULL;
    return event_metadata;
}

NetEvent fillEventStruct(PTRACE_EVENT_INFO event_metadata, PEVENT_RECORD record){
    NetEvent event;
    ZeroMemory(&event, sizeof(event));
    for (ULONG c = 0; c < event_metadata->TopLevelPropertyCount; c++){ // Iterates over the event_metadata properties
        EVENT_PROPERTY_INFO * property_info = &event_metadata->EventPropertyInfoArray[c];
        PWSTR property_name = (PWSTR)((PBYTE)event_metadata + property_info->NameOffset);
        
        PROPERTY_DATA_DESCRIPTOR desc;
        ZeroMemory(&desc, sizeof(desc));
        desc.PropertyName = (ULONGLONG)property_name;
        desc.ArrayIndex = ULONG_MAX;
        DWORD property_size = 0;
        TdhGetPropertySize( // Fails and saves the correct descriptor size inside property_size
            record,
            0,
            NULL,
            1,
            &desc,
            &property_size
        );
        BYTE * buffer = (BYTE*)malloc(property_size);
        TdhGetProperty( // Loads the event data inside the buffer
            record,
            0,
            NULL,
            1,
            &desc,
            property_size,
            buffer
        );

        // Filling the NetEvent struct for better readability and threatment
        PWSTR eventName = (PWSTR)((PBYTE)event_metadata + event_metadata->OpcodeNameOffset);
        if (wcscmp(eventName, SupportedEvents[1]) == 0) event.type = OUTGOING_CONNECTION_EVENT;
        else if (wcscmp(eventName, SupportedEvents[2]) == 0) event.type = INCOMMING_CONNECTION_EVENT;
        else event.type = DISCONNECTION_EVENT;

        USHORT inType = property_info->nonStructType.InType;
        switch (inType)
        {
        case 8: //UINT32
            if (wcscmp(L"daddr", property_name) == 0){// IPv4
                DWORD ip = *(DWORD*)buffer;
                BYTE * b = (BYTE*)&ip;
                if (event.type == OUTGOING_CONNECTION_EVENT || event.type == DISCONNECTION_EVENT){
                    sprintf(event.dest_ip, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
                }else sprintf(event.source_ip, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
            }else if (wcscmp(L"saddr", property_name) == 0){
                DWORD ip = *(DWORD*)buffer;
                BYTE * b = (BYTE*)&ip;
                if (event.type == OUTGOING_CONNECTION_EVENT || event.type == DISCONNECTION_EVENT){
                    sprintf(event.source_ip, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
                }else sprintf(event.dest_ip, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
            }else if (wcscmp(L"PID", property_name) == 0) event.PID = *(DWORD*)buffer;
            break;
        case 6: //UINT16
            if (wcscmp(L"sport", property_name) == 0){
                if (event.type == OUTGOING_CONNECTION_EVENT || event.type == DISCONNECTION_EVENT){
                    event.source_port = ntohs(*(USHORT*)buffer);
                }else event.dest_port = ntohs(*(USHORT*)buffer);
            }else if (wcscmp(L"dport", property_name) == 0){
                if (event.type == OUTGOING_CONNECTION_EVENT || event.type == DISCONNECTION_EVENT){
                    event.dest_port = ntohs(*(USHORT*)buffer);
                }else event.source_port = ntohs(*(USHORT*)buffer);
            }
            break;
        default:
            break;
        }
        free(buffer);
        if (strcmp(event.source_ip, event.dest_ip) == 0 && strlen(event.source_ip) > 0){
            event.type = IRRELEVANT_EVENT;
            return event; // skips connections from 127.0.0.1 -> 127.0.0.1 and similars
        } 
    }   

    // Converts record time format to local time
    FILETIME filetime;
    FileTimeToLocalFileTime((FILETIME *)(&record->EventHeader.TimeStamp), &filetime);
    SYSTEMTIME systemtime;
    FileTimeToSystemTime(&filetime, &systemtime);
    event.moment.year = (unsigned short)systemtime.wYear;
    event.moment.month = (unsigned short)systemtime.wMonth;
    event.moment.day = (unsigned short)systemtime.wDay;
    event.moment.hour = (unsigned short)systemtime.wHour;
    event.moment.minute = (unsigned short)systemtime.wMinute;
    event.moment.second = (unsigned short)systemtime.wSecond;
     
    

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)event.PID);
    DWORD status = GetProcessImageFileNameA(
        hProcess,
        (LPSTR)event.image,
        (DWORD)MAX_PATH
    );
    CloseHandle(hProcess);
    if (!status) {
        //wprintf(L"[-] ERROR: %lu, image file name no retrieved\n", GetLastError());
        ZeroMemory(event.image, 50);
    }
    getImageFromPath(&event);

    return event;
}

// Windows callback function called by ETW at each event from provider
VOID WINAPI Callback(PEVENT_RECORD record){
	signal(SIGINT, terminate);
    // Gets metadata in order to get the actual event data
    PTRACE_EVENT_INFO event_metadata = getEventMetadata(record);
    if (!event_metadata) return;

    // Getting the actual data about the event
    NetEvent event = fillEventStruct(event_metadata, record);
    if (event.type == IRRELEVANT_EVENT) return;
    
    // Output event information
    qSaveEvent(event, Cache);
	if (!suspiciousEvent(&event)) return;
	//wprintf(L"[+] DEBUG: CACHE CURRENT STATE: ");	
	//qPrintQueueSuspicious(Cache);
    printEvent(event);
}

void StartETWTrace(){
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
    ULONG trace_status = StartTrace(
        &sessionHandle,
        KERNEL_LOGGER_NAME,
        properties
    );
    // if (trace_status) wprintf(L"[-] Trace Status: %lu\n", trace_status); Use only for debug
    
    // Opens trace for consuming and defines callback function
    ZeroMemory(&logfile, sizeof(EVENT_TRACE_LOGFILE));
    logfile.LoggerName = KERNEL_LOGGER_NAME;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = Callback;
    traceHandle = OpenTrace(&logfile);
    ProcessTrace(&traceHandle, 1, NULL, NULL);
    CloseTrace(traceHandle);
}

#else
char * SupportedEvents[MAX_EVENTS] = {
    //insert linux event types here
}
#endif 

// Event queue functions
void qInsertEvent(NetEvent event, NetEventQueue q){
    if (q->next == NULL){
        NetEvent * new = (NetEvent*)malloc(sizeof(NetEvent));
        *new = event;
        new->next = NULL;
        q->next = new;
    }else qInsertEvent(event, q->next);
}

void qRemoveEvent(NetEventQueue q){// Always removes the first/older element of the queue
    if (q->next == NULL) return;
    NetEvent * next = q->next->next;
    free(q->next);
    q->next = next;
	EVENT_COUNTER--;
}

void qFree(NetEventQueue q){
    if (q == NULL) return;
    qFree(q->next);
    free(q);
}

int qSaveEvent(NetEvent event, NetEventQueue q){
    if (EVENT_COUNTER >= MAX_CACHE_SIZE) qRemoveEvent(q);
    else EVENT_COUNTER++;
    qInsertEvent(event, q);
    return 1;
}

int inQueue(NetEvent * event, NetEventQueue q, int (*comparison_func)(NetEvent * evt1, NetEvent * evt2)){
    if (q == NULL) return 0;
    if (comparison_func(event, q)) return 1;
    return inQueue(event, q->next, comparison_func);
}

// Event treatment functions
int suspiciousEventImage(NetEvent * event){
    FILE * f = fopen("programs.json", "rb");
    if (!f){
        printf("[-] Error opening \"programs.json\"\n");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char * data = malloc(len + 1);
    fread(data, 1, len, f);
    data[len] = '\0';
    fclose(f);

    // JSON Parsing
    cJSON *json = cJSON_Parse(data);
    free(data);
    if (!json){
        printf("[-] Error in JSON parsing.\n");
        return 1;
    }

    // Accessing "Suspicious" array
    cJSON * suspicious = cJSON_GetObjectItem(json, "Suspicious");
    if (cJSON_IsArray(suspicious)){
        for (cJSON * item = suspicious->child; item; item = item->next){
            if (cJSON_IsString(item)){
                char * sus_image = item->valuestring;
                if (strcmp(event->image, sus_image) == 0) return 1;
            }
        }
    }
    cJSON_Delete(json);
    return 0;
}

NetEventQueue qInitializeQueue(){
	NetEventQueue cache = (NetEvent *)malloc(sizeof(NetEvent));
	strcpy(cache->image,"HEAD");
	cache->next = NULL;
	memset(cache->dest_ip, '\0', sizeof(IPv4));
	memset(cache->source_ip, '\0', sizeof(IPv4));
	cache->dest_port = 0;
	cache->source_port = 0;
	cache->PID = 0;
	cache->type = CACHE_HEAD;
	return cache;
}

void qPrintQueue(NetEventQueue q){
	if (q == NULL){
		wprintf(L"\n");
		return;
	}
	wprintf(L"[%s]->", q->image);
	qPrintQueue(q->next);
}

void qPrintQueueSuspicious(NetEventQueue q){
	if (q == NULL){
		wprintf(L"\n");
		return;
	}else if (q->type == CACHE_HEAD || suspiciousEvent(q)){
		wprintf(L"[%s]->", q->image);
	}
	qPrintQueueSuspicious(q->next);
}

int isConnectionEvent(NetEvent *event){
	return (event->type == INCOMMING_CONNECTION_EVENT || event->type == OUTGOING_CONNECTION_EVENT);
}

int isKnownSysProcess(NetEvent * event){
	char * system_processes[8] = {
		"svchost.exe",
		"msedge.exe",
		"firefox.exe",
		"chrome.exe",
		"lsass.exe",
		"services.exe",
		"System",
		NULL
	};
	for (int c = 0; system_processes[c] != NULL; c++){
		if (strcmp(event->image, system_processes[c]) == 0) return 1;
	}
	return 0;
}

int isBeaconing(NetEvent * event, NetEventQueue q){// Returns 1 if beaconing behavior is detected
	if (event->type != OUTGOING_CONNECTION_EVENT || isKnownSysProcess(event) ) return 0;

	int pairs = 0, beaconing = 0;
    float sum = 0;
	time_t aux1_t = 0, pre_t = 0;
	NetEvent * aux1 = q, * pre = NULL;
		
    while (aux1 != NULL){
		if (sameConnection(event, aux1) && (sameImage(event, aux1) || sameProcess(event, aux1)) && aux1->type == OUTGOING_CONNECTION_EVENT){
			if (pre != NULL){
				aux1_t = timestampToSeconds(aux1->moment);
				pre_t = timestampToSeconds(pre->moment);
				sum += (aux1_t - pre_t);
				pairs++;
			}
		}
		pre = aux1;
        aux1 = aux1->next;
    }
   	if (pairs >= 5 ){
		int media = sum/pairs;
		time_t event_t = timestampToSeconds(event->moment);
		time_t last_interval = event_t - aux1_t;
		if (last_interval >= media-1 && last_interval <= media+1) beaconing = 1;
	}
	return beaconing;
}

int suspiciousEvent(NetEvent * event){
    return suspiciousEventImage(event) || isBeaconing(event, Cache);
}

int sameConnection(NetEvent * evt1, NetEvent * evt2){
	if (!isConnectionEvent(evt1) || !isConnectionEvent(evt2)) return 0;
    if (strcmp(evt1->source_ip, evt2->source_ip) == 0){
        if (strcmp(evt1->dest_ip, evt2->dest_ip) == 0){
            if (evt1->dest_port == evt2->dest_port) return 1;
        }
    }
    
    
    return 0;
}

int sameProcess(NetEvent * evt1, NetEvent * evt2){
	return evt1->PID == evt2->PID;
}

int sameImage(NetEvent * evt1, NetEvent * evt2){
    return ((isConnectionEvent(evt1) && isConnectionEvent(evt2)) && strcmp(evt1->image, evt2->image) == 0);
}

int sameHosts(NetEvent * evt1, NetEvent * evt2){
    return ((isConnectionEvent(evt1) && isConnectionEvent(evt2)) && strcmp(evt1->dest_ip, evt2->dest_ip) == 0);
}

void getImageFromPath(NetEvent * event){
    if (strlen(event->image) == 0) return;
    int path_size = strlen(event->image), i = 0;
    char reverted[path_size];
    ZeroMemory(reverted, path_size);
    for (int c = path_size-1; c >= 0; c--) reverted[i++] = event->image[c];
    ZeroMemory(event->image, 260);
    
    int first_occurrence = strcspn(reverted, "\\");
    char rev_image[first_occurrence];
    ZeroMemory(rev_image, first_occurrence);
    i = 0;
    for (int c = 0; c <= first_occurrence; c++) rev_image[i++] = reverted[c];
    
    char image[first_occurrence];
    ZeroMemory(image, first_occurrence+1);
    i = 0;
    for (int c = first_occurrence-1; c >= 0; c--) image[i++] = rev_image[c];
    strcpy(event->image, image);
}

void printEvent(NetEvent event){
    #if defined(_WIN32)
    wprintf(L"\n[%hu:%hu:%hu] ", event.moment.hour, event.moment.minute, event.moment.second);
    if (event.type == OUTGOING_CONNECTION_EVENT) wprintf(L"Outgoing Connection\n");
    else if (event.type == INCOMMING_CONNECTION_EVENT) wprintf(L"Incomming Connection\n");
    else wprintf(L"Disconnection\n");
    wprintf(L"[+] SUSPICIOUS ACTIVITY DETECTED\n");
    wprintf(L"    PID: %lu\n", event.PID);
    wprintf(L"    Executable: %s\n", event.image);
    wprintf(L"    Source Address: %s:%hu\n", event.source_ip, event.source_port);
    wprintf(L"    Destination Address: %s:%hu\n", event.dest_ip, event.dest_port);
    #else
    if (!suspiciousEventImage(&event)) return;
    printf("\n[%hu:%hu:%hu] ", event.moment.hour, event.moment.minute, event.moment.second);
    if (event.type == OUTGOING_CONNECTION_EVENT) printf("Outgoing Connection\n");
    else if (event.type == INCOMMING_CONNECTION_EVENT) printf("Incomming Connection\n");
    else printf(L"Disconnection\n");
    printf("[+] SUSPICIOUS ACTIVITY DETECTED\n");
    printf("    PID: %lu\n", event.PID);
    printf("    Executable: %s\n", event.image);
    printf("    Source Address: %s:%hu\n", event.source_ip, event.source_port);
    printf("    Destination Address: %s:%hu\n", event.dest_ip, event.dest_port);
    #endif
}

void terminate(int sig){
    printf("[-] CTRL+C detected.\n[-] Terminating.\n");
    if (Cache) qFree(Cache);//free Cache queue if it's not empty
    exit(0);
}
time_t timestampToSeconds(Timestamp timestamp){
    struct tm t = {0};
    t.tm_year = timestamp.year;
    t.tm_mon = timestamp.month;
    t.tm_mday = timestamp.day;
	t.tm_hour = timestamp.hour;
	t.tm_sec = timestamp.second;
	time_t seconds = mktime(&t);
	return seconds;
}

int main(){
    Cache =	qInitializeQueue();
    Cache->next = NULL;
    #if defined(_WIN32)

    wprintf(L"\n==== NETWATCH STARTED ====\n");
    StartETWTrace();

    #else 

    printf("\n==== NETWATCH STARTED ====\n");

    #endif
    return 0;
}

