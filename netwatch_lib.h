#define MAX_EVENTS 3
#define INCOMMING_CONNECTION_EVENT 2
#define OUTGOING_CONNECTION_EVENT 1
#define DISCONNECTION_EVENT 0
#define IRRELEVANT_EVENT -1
#define CACHE_HEAD 3
#include <string.h>
#include <signal.h>
#include <time.h>
#include "cJSON/cJSON.h"

// Types and structs
typedef char IPv4[20];
typedef struct {
    unsigned short year;
    unsigned short month;
    unsigned short day;
    unsigned short hour;
    unsigned short minute;
    unsigned short second;
} Timestamp;
typedef struct netevent{
    int PID;
    char image[260];
    short int type;
    IPv4 source_ip;
    unsigned short source_port;
    IPv4 dest_ip;
    unsigned short dest_port;
    Timestamp moment;
    struct netevent * next;
} NetEvent;
typedef NetEvent* NetEventQueue; // A NetEvent queue (first-in first-out data structure) implemented with singly linked list

// Event queue management functions
void qInsertEvent(NetEvent event, NetEventQueue q);
void qRemoveEvent(NetEventQueue qe);// Always removes the first/older element of the Queue
void qFree(NetEventQueue q);// Free all nodes of the queue recursively
void qPrintQueue(NetEventQueue q);
void qPrintQueueSuspicious(NetEventQueue q);
int qSaveEvent(NetEvent event, NetEventQueue q);
int inQueue(NetEvent * event, NetEventQueue q, int (*comparison_func)(NetEvent * evt1, NetEvent * evt2)); //Takes an event pointer, a queue and a choice-free NetEvent comparison function


// Event treatment functions
int sameConnection(NetEvent * evt1, NetEvent * evt2);
int sameImage(NetEvent * evt1, NetEvent * evt2);
int sameHosts(NetEvent * evt1, NetEvent * evt2);
int sameProcess(NetEvent * evt1, NetEvent * evt2);
int suspiciousEventImage(NetEvent * event);
int isConnectionEvent(NetEvent * event);
int isKnownSysProcess(NetEvent * event);
int isBeaconing(NetEvent * event, NetEventQueue q);
void getImageFromPath(NetEvent * event);
void printEvent(NetEvent event);
int suspiciousEvent(NetEvent * event, int * beaconing_interval, int * suspicious_image);

// Others
void terminate(int sig);
time_t timestampToSeconds(Timestamp timestamp);

//Windows includes and functions
#if defined(_WIN32)

#define INITGUID 
#include <winsock2.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <psapi.h>
PWSTR SupportedEvents[MAX_EVENTS] = {
    (PWSTR)L"DisconnectIPV4",
    (PWSTR)L"ConnectIPV4",
    (PWSTR)L"AcceptIPV4"
};
TRACEHANDLE sessionHandle = 0;// Trace session handler
TRACEHANDLE traceHandle = 0; 

int isEventSupported(PTRACE_EVENT_INFO event_metadata);
PTRACE_EVENT_INFO getEventMetadata(PEVENT_RECORD record);
NetEvent fillEventStruct(PTRACE_EVENT_INFO event_metadata, PEVENT_RECORD record);
VOID WINAPI Callback(PEVENT_RECORD record);
void StartETWTrace();

#endif
