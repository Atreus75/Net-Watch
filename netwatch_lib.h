#define MAX_EVENTS 2
#define CONNECTION_EVENT 1
#define DISCONNECTION_EVENT 0
#define IRRELEVANT_EVENT -1
#include <string.h>

typedef char IPv4[20];
typedef struct {
    unsigned short hour;
    unsigned short minute;
    unsigned short second;
} Timestamp;
typedef struct {
    int PID;
    char image[50];
    short int type; // 1 for Connection, 0 for Disconnection
    IPv4 source_ip;
    unsigned short source_port;
    IPv4 dest_ip;
    unsigned short dest_port;
    Timestamp moment;
} NetEvent;

int SupportedEvents[MAX_EVENTS] = {
    12,
    13
};

int isOpcodeSupported(unsigned char opcode){
    for (int c = 0; c<MAX_EVENTS; c++) if (SupportedEvents[c] == opcode) return 1;
    return 0;
}

int sameConnection(NetEvent * evt1, NetEvent * evt2){
    if (evt1->PID == evt2->PID){
        if (strcmp(evt1->source_ip, evt2->source_ip) == 0){
            if (strcmp(evt1->dest_ip, evt2->dest_ip) == 0){
                if (evt1->source_port == evt2->source_port){
                    if (evt1->dest_port == evt2->dest_port) return 1;
                }
            }
        }
    }
    
    return 0;
}

int inCache(NetEvent * event, NetEvent * Cache, int evt_count){// Checks if the given event is in EventCache. If so, returns a non-negative integer indicating the position of the event in the 
    for (int c = 0; c < evt_count; c++) if (sameConnection(event, &(Cache[c]) )) return c;
    return -1;
}
