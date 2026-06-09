#define MAX_EVENTS 3
#define INCOMMING_CONNECTION_EVENT 2
#define OUTGOING_CONNECTION_EVENT 1
#define DISCONNECTION_EVENT 0
#define IRRELEVANT_EVENT -1
#include <string.h>
#include <signal.h>
#include "cJSON.h"

// Types and structs
typedef char IPv4[20];
typedef struct {
    unsigned short hour;
    unsigned short minute;
    unsigned short second;
} Timestamp;
typedef struct netevent{
    int PID;
    char image[260];
    short int type; // 1 for Connection, 0 for Disconnection
    IPv4 source_ip;
    unsigned short source_port;
    IPv4 dest_ip;
    unsigned short dest_port;
    Timestamp moment;
    struct netevent * next;
} NetEvent;
typedef NetEvent* NetEventCache; // A NetEvent queue (first-in first-out data structure) implemented with singly linked list

// Event queue management functions
void insertEvent(NetEvent event, NetEventCache queue);
void removeEvent(NetEventCache queue);// Always removes the first/older element of the Queue
void freeQueue(NetEventCache queue);// Free all nodes of the queue recursively
int saveEvent(NetEvent event, NetEventCache queue);

// Event treatment functions
int sameConnection(NetEvent * evt1, NetEvent * evt2);
int suspiciousEventImage(NetEvent * event);
int suspiciousEvent(NetEvent * event);
void getImageFromPath(NetEvent * event);
void printEvent(NetEvent event);

// Others
void terminate(int sig);

// Idea: make several comparison functions and then pass the comparing function as an argument of this function below
int inCache(NetEvent * event, NetEventCache queue);

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
