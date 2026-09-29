#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "windivert.h"

#if defined(__has_include) && __has_include("model.h")
#include "model.h"
#define ADOS_MODEL_AVAILABLE 1
#else
#define ADOS_FEATURE_COUNT 4
#define ADOS_MODEL_AVAILABLE 0
static float ados_model_score(const float features[4]) { (void)features; return 0.0f; }
#endif

#define FLOW_CAP 8192u
#define FLOW_PROBES 16u
#define DEST_CAP 256u
#define DEST_PROBES 8u
#define BATCH_CAP 64u
#define PACKET_CAP 65535u
#define BATCH_BYTES (BATCH_CAP * PACKET_CAP)
#define WINDOW_MS 1000u
#define STOP_EVENT_NAME L"Local\\AdosAiProtectionStop_v1"
#define MUTEX_NAME L"Local\\AdosAiProtectionInstance_v1"
#define SYN_DEFAULT 250u
#define UDP_DEFAULT 10000u
#define GLOBAL_SYN_DEFAULT 2000u
#define GLOBAL_UDP_DEFAULT 50000u

typedef struct { uint8_t family, protocol; uint16_t local_port; uint8_t remote[16]; } FlowKey;
typedef struct { FlowKey key; uint64_t start_ms; uint32_t packets, bytes, syns, udps; uint8_t used; } FlowEntry;
typedef struct { const uint8_t *data; UINT len; WINDIVERT_ADDRESS addr; } PacketRef;
static FlowEntry g_flows[FLOW_CAP];
static FlowEntry g_destinations[DEST_CAP];
static uint8_t g_rx[BATCH_BYTES],g_tx[BATCH_BYTES];
static WINDIVERT_ADDRESS g_rx_addr[BATCH_CAP],g_tx_addr[BATCH_CAP];
static uint64_t g_seen,g_dropped,g_malformed,g_untracked,g_dest_untracked,g_scored;
static float g_last_score;
static uint32_t g_syn_limit=SYN_DEFAULT,g_udp_limit=UDP_DEFAULT;
static uint32_t g_global_syn_limit=GLOBAL_SYN_DEFAULT,g_global_udp_limit=GLOBAL_UDP_DEFAULT;
static int g_observe;
static wchar_t g_status_path[MAX_PATH];
static CRITICAL_SECTION g_status_lock;
static int g_status_lock_ready;
static HANDLE g_control_event,g_shutdown_complete;
static char g_last_event[64]="runtime_starting",g_previous_event[64]="none";

static void record_event(const char *event) {
    if(g_status_lock_ready) EnterCriticalSection(&g_status_lock);
    if(strcmp(g_last_event,event)==0) { if(g_status_lock_ready) LeaveCriticalSection(&g_status_lock); return; }
    strncpy(g_previous_event,g_last_event,sizeof(g_previous_event)-1); g_previous_event[sizeof(g_previous_event)-1]=0;
    strncpy(g_last_event,event,sizeof(g_last_event)-1); g_last_event[sizeof(g_last_event)-1]=0;
    if(g_status_lock_ready) LeaveCriticalSection(&g_status_lock);
}

static uint64_t now_ms(void) { return GetTickCount64(); }
static uint32_t hash_key(const FlowKey *k) {
    const uint8_t *p=(const uint8_t*)k; uint32_t h=2166136261u;
    for(size_t i=0;i<sizeof(*k);i++) { h^=p[i]; h*=16777619u; } return h;
}
static int key_eq(const FlowKey *a,const FlowKey *b) { return memcmp(a,b,sizeof(*a))==0; }
static int private4(const uint8_t *a) {
    return a[0]==10 || (a[0]==172 && (a[1]&0xf0)==16) || (a[0]==192 && a[1]==168) ||
      (a[0]==169 && a[1]==254) || a[0]==127 || a[0]==0 || a[0]>=224 ||
      (a[0]==100 && (a[1]&0xc0)==64);
}
static int private6(const uint8_t *a) {
    int loop=1; for(int i=0;i<15;i++) if(a[i]) { loop=0; break; } loop=loop && a[15]==1;
    static const uint8_t mapped[12]={0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    return loop || (a[0]&0xfe)==0xfc || (a[0]==0xfe && (a[1]&0xc0)==0x80) || a[0]==0xff ||
      (memcmp(a,mapped,sizeof(mapped))==0 && private4(a+12));
}
static int private_remote(uint8_t family,const uint8_t *a) { return family==4?private4(a):private6(a); }
static int packet_len(const uint8_t *p,size_t remain,uint32_t *len) {
    if(remain<1) return 0;
    if((p[0]>>4)==4) {
        if(remain<20) return 0; uint32_t ihl=(p[0]&15u)*4u,n=((uint32_t)p[2]<<8)|p[3];
        if(ihl<20 || n<ihl || n>remain) return 0; *len=n; return 1;
    }
    if((p[0]>>4)==6) {
        if(remain<40) return 0; uint32_t n=40u+(((uint32_t)p[4]<<8)|p[5]);
        if(n>remain) return 0; *len=n; return 1;
    }
    return 0;
}
static void score_window(const FlowEntry *e,uint64_t elapsed) {
    if(!e->packets || ADOS_FEATURE_COUNT!=4) return;
    float f[4];
    (void)elapsed;
    f[0]=(float)e->packets;
    f[1]=(float)e->bytes/(float)e->packets;
    f[2]=(float)e->syns/(float)e->packets;
    f[3]=(float)e->udps/(float)e->packets;
    float score=ados_model_score(f);
    if(score==score && score<1.0e20f && score>-1.0e20f) { g_last_score=score; g_scored++; }
}
static FlowEntry *flow_get(const FlowKey *key,uint64_t t) {
    uint32_t base=hash_key(key)%FLOW_CAP; FlowEntry *available=NULL;
    for(uint32_t i=0;i<FLOW_PROBES;i++) {
        FlowEntry *e=&g_flows[(base+i)%FLOW_CAP];
        if(e->used && key_eq(&e->key,key)) {
            uint64_t age=t-e->start_ms;
            if(age<WINDOW_MS) return e;
            score_window(e,age); memset(e,0,sizeof(*e)); e->used=1; e->key=*key; e->start_ms=t; return e;
        }
        if(!e->used && !available) available=e;
        else if(e->used && t-e->start_ms>=WINDOW_MS && !available) available=e;
    }
    if(!available) { g_untracked++; return NULL; }
    if(available->used) score_window(available,t-available->start_ms);
    memset(available,0,sizeof(*available)); available->used=1; available->key=*key; available->start_ms=t;
    return available;
}
static FlowEntry *destination_get(const FlowKey *key,uint64_t t) {
    uint32_t base=hash_key(key)%DEST_CAP; FlowEntry *available=NULL;
    for(uint32_t i=0;i<DEST_PROBES;i++) {
        FlowEntry *e=&g_destinations[(base+i)%DEST_CAP];
        if(e->used && key_eq(&e->key,key)) {
            if(t-e->start_ms<WINDOW_MS) return e;
            memset(e,0,sizeof(*e));e->used=1;e->key=*key;e->start_ms=t;return e;
        }
        if(!e->used && !available) available=e;
        else if(e->used && t-e->start_ms>=WINDOW_MS && !available) available=e;
    }
    if(!available) { g_dest_untracked++; return NULL; }
    memset(available,0,sizeof(*available));available->used=1;available->key=*key;available->start_ms=t;return available;
}
/* Filter sees inbound UDP and TCP SYN only. Every uncertain/unsupported case passes. */
static int inspect_packet(const uint8_t *p,UINT n,const WINDIVERT_ADDRESS *a,uint64_t t) {
    if(a->Outbound || a->Loopback || a->Impostor) return 0;
    PWINDIVERT_IPHDR ip4=NULL; PWINDIVERT_IPV6HDR ip6=NULL; PWINDIVERT_TCPHDR tcp=NULL;
    PWINDIVERT_UDPHDR udp=NULL; UINT8 protocol=0;
    if(!WinDivertHelperParsePacket(p,n,&ip4,&ip6,&protocol,NULL,NULL,&tcp,&udp,NULL,NULL,NULL,NULL)) { g_malformed++; return 0; }
    uint8_t family=ip4?4:ip6?6:0, remote[16]={0}; uint16_t port=0;
    if(ip4) {
        if(WINDIVERT_IPHDR_GET_FRAGOFF(ip4)!=0 || WINDIVERT_IPHDR_GET_MF(ip4)) return 0;
        memcpy(remote,&ip4->SrcAddr,4);
        if(tcp) port=WinDivertHelperNtohs(tcp->DstPort); else if(udp) port=WinDivertHelperNtohs(udp->DstPort);
    } else if(ip6) {
        if(ip6->NextHdr!=IPPROTO_TCP && ip6->NextHdr!=IPPROTO_UDP) return 0;
        memcpy(remote,ip6->SrcAddr,16);
        if(tcp) port=WinDivertHelperNtohs(tcp->DstPort); else if(udp) port=WinDivertHelperNtohs(udp->DstPort);
    } else return 0;
    if(!tcp && !udp) return 0;
    if(tcp && (!tcp->Syn || tcp->Ack)) return 0;
    if(!port || private_remote(family,remote)) return 0;
    FlowKey key; memset(&key,0,sizeof(key)); key.family=family; key.protocol=protocol; key.local_port=port;
    memcpy(key.remote,remote,family==4?4:16);
    FlowEntry *e=flow_get(&key,t);
    if(e) { e->packets++; e->bytes+=n; if(tcp) e->syns++; if(udp) e->udps++; }
    FlowKey dest=key; memset(dest.remote,0,sizeof(dest.remote));
    FlowEntry *d=destination_get(&dest,t);
    if(d) { d->packets++; if(tcp) d->syns++; if(udp) d->udps++; }
    if(tcp) {
        int drop=!g_observe && ((e && e->syns>g_syn_limit) || (d && d->syns>g_global_syn_limit));
        if(drop) record_event("tcp_syn_rate_cap"); return drop;
    }
    int drop=!g_observe && ((e && e->udps>g_udp_limit) || (d && d->udps>g_global_udp_limit));
    if(drop) record_event("udp_rate_cap"); return drop;
}
static void status_path(void) {
    wchar_t exe[MAX_PATH]; DWORD n=GetModuleFileNameW(NULL,exe,MAX_PATH);
    if(!n || n>=MAX_PATH) { wcscpy(g_status_path,L"ados-status.txt"); return; }
    wchar_t *slash=wcsrchr(exe,L'\\'); if(!slash) { wcscpy(g_status_path,L"ados-status.txt"); return; }
    slash[1]=L'\0'; _snwprintf(g_status_path,MAX_PATH-1,L"%lsados-status.txt",exe);
}
static void write_status(const char *state,const char *detail) {
    if(g_status_lock_ready) EnterCriticalSection(&g_status_lock);
    wchar_t tmp[MAX_PATH]; _snwprintf(tmp,MAX_PATH-1,L"%ls.tmp",g_status_path);
    FILE *f=_wfopen(tmp,L"wb"); if(!f) { if(g_status_lock_ready) LeaveCriticalSection(&g_status_lock); return; }
    SYSTEMTIME utc; GetSystemTime(&utc);
    fprintf(f,"state=%s\npid=%lu\nmode=%s\nbackend=WinDivert-network-layer\nmodel=%s\nmodel_enforcement=disabled\nsyn_limit_per_remote_per_second=%u\nudp_limit_per_remote_per_second=%u\nglobal_syn_limit_per_destination_port_per_second=%u\nglobal_udp_limit_per_destination_port_per_second=%u\nseen=%llu\ndropped=%llu\nmalformed_fail_open=%llu\nuntracked_fail_open=%llu\ndestination_untracked_fail_open=%llu\nmodel_scored=%llu\nlast_model_score=%.6f\nlast_event=%s\nprevious_event=%s\nheartbeat_utc=%04u-%02u-%02uT%02u:%02u:%02uZ\ndetail=%s\n",
      state,(unsigned long)GetCurrentProcessId(),g_observe?"observe":"enforce",ADOS_MODEL_AVAILABLE?"available_advisory":"unavailable_advisory",g_syn_limit,g_udp_limit,g_global_syn_limit,g_global_udp_limit,
      (unsigned long long)g_seen,(unsigned long long)g_dropped,(unsigned long long)g_malformed,
      (unsigned long long)g_untracked,(unsigned long long)g_dest_untracked,(unsigned long long)g_scored,(double)g_last_score,g_last_event,g_previous_event,
      utc.wYear,utc.wMonth,utc.wDay,utc.wHour,utc.wMinute,utc.wSecond,detail?detail:"none");
    fclose(f); MoveFileExW(tmp,g_status_path,MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH);
    if(g_status_lock_ready) LeaveCriticalSection(&g_status_lock);
}
static HMODULE load_dll(void) {
    wchar_t exe[MAX_PATH],path[MAX_PATH]; DWORD n=GetModuleFileNameW(NULL,exe,MAX_PATH);
    if(!n || n>=MAX_PATH) return NULL; wchar_t *slash=wcsrchr(exe,L'\\'); if(!slash) return NULL; slash[1]=L'\0';
    _snwprintf(path,MAX_PATH-1,L"%lsWinDivert.dll",exe);
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32|LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
    return LoadLibraryExW(path,NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
}
typedef struct { HANDLE event, parent, divert; uint64_t deadline_ms; } Watchdog;
static DWORD WINAPI watchdog(void *arg) {
    Watchdog *w=(Watchdog*)arg; HANDLE handles[2]={w->event,w->parent}; DWORD count=w->parent?2:1;
    for(;;) {
        DWORD delay=1000;
        if(w->deadline_ms) { uint64_t now=now_ms(); if(now>=w->deadline_ms) delay=0; else if(w->deadline_ms-now<delay) delay=(DWORD)(w->deadline_ms-now); }
        DWORD r=WaitForMultipleObjects(count,handles,FALSE,delay);
        if(r==WAIT_OBJECT_0) { record_event("stop_requested"); write_status("stopping","stop event received"); WinDivertShutdown(w->divert,WINDIVERT_SHUTDOWN_RECV); return 0; }
        if(count==2 && r==WAIT_OBJECT_0+1) { SetEvent(w->event); record_event("parent_process_exit"); write_status("stopping","parent process exited"); WinDivertShutdown(w->divert,WINDIVERT_SHUTDOWN_RECV); return 0; }
        if(r==WAIT_TIMEOUT) {
            if(w->deadline_ms && now_ms()>=w->deadline_ms) { SetEvent(w->event); record_event("duration_complete"); write_status("stopping","duration complete"); WinDivertShutdown(w->divert,WINDIVERT_SHUTDOWN_RECV); return 0; }
            write_status("active","heartbeat"); continue;
        }
        record_event("watchdog_wait_error"); write_status("error","watchdog wait failed"); WinDivertShutdown(w->divert,WINDIVERT_SHUTDOWN_RECV); return 0;
    }
}
static BOOL WINAPI console_handler(DWORD type) {
    if(type!=CTRL_C_EVENT && type!=CTRL_BREAK_EVENT && type!=CTRL_CLOSE_EVENT && type!=CTRL_LOGOFF_EVENT && type!=CTRL_SHUTDOWN_EVENT) return FALSE;
    if(g_control_event) SetEvent(g_control_event);
    if((type==CTRL_CLOSE_EVENT || type==CTRL_LOGOFF_EVENT || type==CTRL_SHUTDOWN_EVENT) && g_shutdown_complete)
        WaitForSingleObject(g_shutdown_complete,4500);
    return TRUE;
}
static int run_loop(int observe,DWORD seconds,DWORD parent_pid) {
    InitializeCriticalSection(&g_status_lock); g_status_lock_ready=1; status_path();
    g_observe=observe; HANDLE mutex=CreateMutexW(NULL,FALSE,MUTEX_NAME);
    if(!mutex) { fprintf(stderr,"mutex_error=%lu\n",GetLastError()); return 2; }
    if(GetLastError()==ERROR_ALREADY_EXISTS) { fprintf(stderr,"already_running\n"); CloseHandle(mutex); return 3; }
    HANDLE event=CreateEventW(NULL,TRUE,FALSE,STOP_EVENT_NAME);
    if(!event) { fprintf(stderr,"event_error=%lu\n",GetLastError()); CloseHandle(mutex); return 2; }
    g_control_event=event; g_shutdown_complete=CreateEventW(NULL,TRUE,FALSE,NULL);
    if(!g_shutdown_complete) { fprintf(stderr,"shutdown_event_error=%lu\n",GetLastError()); CloseHandle(event); CloseHandle(mutex); return 2; }
    SetConsoleCtrlHandler(console_handler,TRUE);
    HANDLE parent=NULL;
    if(parent_pid) {
        if(parent_pid==GetCurrentProcessId() || !(parent=OpenProcess(SYNCHRONIZE,FALSE,parent_pid))) {
            fprintf(stderr,"invalid parent process %lu: %lu\n",(unsigned long)parent_pid,GetLastError());
            SetConsoleCtrlHandler(console_handler,FALSE); CloseHandle(g_shutdown_complete); CloseHandle(event); CloseHandle(mutex); return 2;
        }
        if(WaitForSingleObject(parent,0)==WAIT_OBJECT_0) { fprintf(stderr,"parent process already exited\n"); CloseHandle(parent); SetConsoleCtrlHandler(console_handler,FALSE); CloseHandle(g_shutdown_complete); CloseHandle(event); CloseHandle(mutex); return 2; }
    }
    HMODULE dll=load_dll(); if(!dll) { fprintf(stderr,"WinDivert.dll missing\n"); if(parent)CloseHandle(parent); SetConsoleCtrlHandler(console_handler,FALSE); CloseHandle(g_shutdown_complete); CloseHandle(event); CloseHandle(mutex); return 2; }
    UINT64 flags=observe?(WINDIVERT_FLAG_SNIFF|WINDIVERT_FLAG_RECV_ONLY):0;
    HANDLE wd=WinDivertOpen("inbound and !loopback and !impostor and (udp or (tcp and tcp.Syn and !tcp.Ack))",WINDIVERT_LAYER_NETWORK,0,flags);
    if(wd==INVALID_HANDLE_VALUE) { fprintf(stderr,"WinDivertOpen failed: %lu (elevation/signature/driver check required)\n",GetLastError()); FreeLibrary(dll); if(parent)CloseHandle(parent); SetConsoleCtrlHandler(console_handler,FALSE); CloseHandle(g_shutdown_complete); CloseHandle(event); CloseHandle(mutex); return 2; }
    if(!WinDivertSetParam(wd,WINDIVERT_PARAM_QUEUE_LENGTH,1024) ||
       !WinDivertSetParam(wd,WINDIVERT_PARAM_QUEUE_TIME,1000) ||
       !WinDivertSetParam(wd,WINDIVERT_PARAM_QUEUE_SIZE,4u*1024u*1024u)) {
        DWORD err=GetLastError(); status_path(); write_status("error","WinDivert queue configuration failed");
        fprintf(stderr,"WinDivertSetParam failed: %lu\n",err); WinDivertShutdown(wd,WINDIVERT_SHUTDOWN_BOTH);
        WinDivertClose(wd); FreeLibrary(dll); if(parent)CloseHandle(parent); SetConsoleCtrlHandler(console_handler,FALSE); CloseHandle(g_shutdown_complete); CloseHandle(event); CloseHandle(mutex); return 2;
    }
    Watchdog w={event,parent,wd,seconds?now_ms()+(uint64_t)seconds*1000u:0}; HANDLE thread=CreateThread(NULL,0,watchdog,&w,0,NULL);
    if(!thread) { WinDivertShutdown(wd,WINDIVERT_SHUTDOWN_BOTH); WinDivertClose(wd); FreeLibrary(dll); if(parent)CloseHandle(parent); SetConsoleCtrlHandler(console_handler,FALSE); CloseHandle(g_shutdown_complete); CloseHandle(event); CloseHandle(mutex); return 2; }
    record_event("capture_active"); write_status("active","WinDivert handle open; inbound UDP and TCP SYN scope");
    fprintf(stderr,"active mode=%s syn_limit=%u udp_limit=%u global_syn_limit=%u global_udp_limit=%u model=%s advisory_only=1\n",observe?"observe":"enforce",g_syn_limit,g_udp_limit,g_global_syn_limit,g_global_udp_limit,ADOS_MODEL_AVAILABLE?"available":"unavailable");
    int result=0;
    for(;;) {
        UINT bytes=0,addr_bytes=sizeof(g_rx_addr);
        if(!WinDivertRecvEx(wd,g_rx,sizeof(g_rx),&bytes,0,g_rx_addr,&addr_bytes,NULL)) {
            DWORD err=GetLastError();
            DWORD stop_state=WaitForSingleObject(event,0);
            if(stop_state==WAIT_OBJECT_0 && (err==ERROR_NO_DATA || err==ERROR_NO_MORE_ITEMS || err==ERROR_OPERATION_ABORTED)) break;
            if(err==ERROR_OPERATION_ABORTED || err==ERROR_NO_MORE_ITEMS || err==ERROR_IO_PENDING || err==ERROR_INVALID_HANDLE || err==ERROR_NO_DATA) {
                write_status("error","unexpected WinDivertRecvEx termination");
                fprintf(stderr,"receive_error=%lu\n",err); result=2; break;
            }
            write_status("error","WinDivertRecvEx failed"); fprintf(stderr,"receive_error=%lu\n",err); result=2; break;
        }
        UINT count=addr_bytes/(UINT)sizeof(WINDIVERT_ADDRESS); if(count>BATCH_CAP) count=BATCH_CAP;
        PacketRef refs[BATCH_CAP]; UINT nr=0; size_t off=0;
        for(UINT i=0;i<count && off<bytes;i++) {
            uint32_t n=0; if(!packet_len(g_rx+off,(size_t)bytes-off,&n)) break;
            refs[nr].data=g_rx+off; refs[nr].len=n; refs[nr].addr=g_rx_addr[i]; nr++; off+=n;
        }
        if(off!=bytes || nr!=count) {
            /* Unknown batch boundaries cannot be safely changed; fail visibly. */
            write_status("error","packet batch framing invalid; capture stopped"); fprintf(stderr,"batch_framing_error\n"); result=2; break;
        }
        size_t txoff=0; UINT txcount=0; uint64_t t=now_ms(); int capacity_error=0;
        EnterCriticalSection(&g_status_lock);
        for(UINT i=0;i<nr;i++) {
            g_seen++; int drop=inspect_packet(refs[i].data,refs[i].len,&refs[i].addr,t);
            if(drop && !observe) { g_dropped++; continue; }
            if(txoff+refs[i].len>sizeof(g_tx) || txcount>=BATCH_CAP) { capacity_error=1; break; }
            memcpy(g_tx+txoff,refs[i].data,refs[i].len); txoff+=refs[i].len; g_tx_addr[txcount++]=refs[i].addr;
        }
        LeaveCriticalSection(&g_status_lock);
        if(capacity_error) { record_event("reinject_capacity_error"); write_status("error","reinject batch capacity exceeded"); result=2; break; }
        if(txcount && !observe) {
            UINT sent=0; BOOL ok=WinDivertSendEx(wd,g_tx,(UINT)txoff,&sent,0,g_tx_addr,txcount*(UINT)sizeof(WINDIVERT_ADDRESS),NULL);
            if(!ok || sent!=txoff) { write_status("error","WinDivertSendEx failed"); fprintf(stderr,"send_error=%lu\n",GetLastError()); result=2; break; }
        }
    }
    record_event(result==0?"capture_stopped":"runtime_error");
    SetEvent(event); WaitForSingleObject(thread,INFINITE);
    WinDivertShutdown(wd,WINDIVERT_SHUTDOWN_BOTH); WinDivertClose(wd);
    CloseHandle(thread); FreeLibrary(dll);
    if(result==0) write_status("stopped","handle closed; filtering is inactive");
    else write_status("error","runtime stopped after an error; filtering is inactive");
    SetEvent(g_shutdown_complete); SetConsoleCtrlHandler(console_handler,FALSE); g_control_event=NULL;
    if(parent)CloseHandle(parent); CloseHandle(g_shutdown_complete); CloseHandle(event); CloseHandle(mutex); return result;
}
static int status_cmd(void) {
    HANDLE m=OpenMutexW(SYNCHRONIZE,FALSE,MUTEX_NAME);
    if(!m) { DWORD err=GetLastError(); if(err==ERROR_FILE_NOT_FOUND) { puts("state=stopped\nreason=runtime mutex absent"); return 0; }
        fprintf(stderr,"state=unknown\nreason=runtime mutex query failed error=%lu\n",err); return 2; }
    status_path(); FILE *f=_wfopen(g_status_path,L"rb"); if(!f) { puts("state=starting"); CloseHandle(m); return 0; }
    char b[2048]; size_t n=fread(b,1,sizeof(b)-1,f); fclose(f); b[n]=0; fputs(b,stdout); CloseHandle(m); return 0;
}
static int self_test(void) {
    HMODULE dll=load_dll(); if(!dll) { fprintf(stderr,"self_test needs dist\\WinDivert.dll: %lu\n",GetLastError()); return 2; }
    uint8_t v4[28]={0x45,0,0,28,0,0,0,0,64,17,0,0,8,8,8,8,192,168,1,4,0x13,0x89,0,53,0,8,0,0};
    uint8_t v6[48]={0x60,0,0,0,0,8,17,64,0x20,1,0x48,0x60,0,0,0,0,0,0,0,0,0,0,0,1,0x20,1,0x48,0x60,0,0,0,0,0,0,0,0,0,0,0,2,0x13,0x89,0,53,0,8,0,0};
    uint8_t syn[40]={0x45,0,0,40,0,0,0,0,64,6,0,0,8,8,4,4,192,168,1,4,0x13,0x89,0,80,0,0,0,1,0,0,0,0,0x50,0x02,0,0,0,0,0,0};
    uint8_t ack[40]; memcpy(ack,syn,sizeof(ack)); ack[33]=0x10;
    WINDIVERT_ADDRESS a; memset(&a,0,sizeof(a)); uint64_t t=100;
    g_observe=0; g_syn_limit=2; g_udp_limit=2; g_global_syn_limit=2; g_global_udp_limit=2;
    memset(g_flows,0,sizeof(g_flows)); memset(g_destinations,0,sizeof(g_destinations));
    uint8_t v4_other[28]; memcpy(v4_other,v4,sizeof(v4)); v4_other[15]=9;
    uint8_t v4_third[28]; memcpy(v4_third,v4,sizeof(v4)); v4_third[15]=10;
    g_udp_limit=99;
    if(inspect_packet(v4,sizeof(v4),&a,t)!=0 || inspect_packet(v4_other,sizeof(v4_other),&a,t)!=0 || inspect_packet(v4_third,sizeof(v4_third),&a,t)!=1) goto fail;
    g_observe=1; if(inspect_packet(v4,sizeof(v4),&a,t)!=0) goto fail;
    g_observe=0;
    memset(g_flows,0,sizeof(g_flows)); memset(g_destinations,0,sizeof(g_destinations));
    g_udp_limit=2; g_global_udp_limit=99;
    if(inspect_packet(v4,sizeof(v4),&a,t)!=0 || inspect_packet(v4,sizeof(v4),&a,t)!=0 || inspect_packet(v4,sizeof(v4),&a,t)!=1) goto fail;
    memset(g_flows,0,sizeof(g_flows)); memset(g_destinations,0,sizeof(g_destinations));
    uint8_t syn_other[40]; memcpy(syn_other,syn,sizeof(syn));syn_other[15]=5;
    uint8_t syn_third[40]; memcpy(syn_third,syn,sizeof(syn));syn_third[15]=6;
    g_global_syn_limit=2; g_syn_limit=99;
    if(inspect_packet(syn,sizeof(syn),&a,t)!=0 || inspect_packet(syn_other,sizeof(syn_other),&a,t)!=0 || inspect_packet(syn_third,sizeof(syn_third),&a,t)!=1) goto fail;
    if(inspect_packet(ack,sizeof(ack),&a,t)!=0) goto fail;
    memset(g_flows,0,sizeof(g_flows)); memset(g_destinations,0,sizeof(g_destinations));
    if(inspect_packet(v6,sizeof(v6),&a,t)!=0) goto fail;
    uint8_t private_udp[28]; memcpy(private_udp,v4,sizeof(v4)); private_udp[12]=192;private_udp[13]=168;private_udp[14]=1;private_udp[15]=1;
    if(inspect_packet(private_udp,sizeof(private_udp),&a,t)!=0) goto fail;
    uint8_t malformed[4]={0x45,0,0,28}; if(inspect_packet(malformed,sizeof(malformed),&a,t)!=0) goto fail;
    memset(g_flows,0,sizeof(g_flows)); FlowKey key={0};key.family=4;key.protocol=17;key.local_port=53;key.remote[0]=8;
    if(!flow_get(&key,t) || !flow_get(&key,t+WINDOW_MS)) goto fail;
    memset(g_flows,0,sizeof(g_flows)); for(uint32_t i=0;i<FLOW_CAP;i++){g_flows[i].used=1;g_flows[i].start_ms=t;}
    if(flow_get(&key,t)!=NULL) goto fail;
    float features[4]={1,64,0,1}; float score=ados_model_score(features); if(!(score==score && score<1.0e20f && score>-1.0e20f)) goto fail;
    FreeLibrary(dll); puts("self_test=passed ipv4_udp ipv6_udp tcp_syn_ack source_and_port_caps observe private malformed expiry flow_saturation model_finite"); return 0;
fail:
    FreeLibrary(dll); fprintf(stderr,"self_test=failed\n"); return 1;
}
static int benchmark(void) {
    FlowKey k={0}; k.family=4;k.protocol=17;k.local_port=443;k.remote[0]=8;k.remote[1]=8;k.remote[2]=8;k.remote[3]=8;
    memset(g_flows,0,sizeof(g_flows)); float f[4]={10000,512,0.0f,1.0f}; volatile float score=0;
    const uint64_t loops=1000000; uint64_t start=now_ms();
    for(uint64_t i=0;i<loops;i++) { k.remote[3]=(uint8_t)(i%256); FlowEntry *e=flow_get(&k,start+(i/256)%WINDOW_MS); if(e) { e->packets++;e->udps++; } score+=ados_model_score(f); }
    uint64_t elapsed=now_ms()-start; if(!elapsed) elapsed=1;
    printf("benchmark=offline iterations=%llu elapsed_ms=%llu operations_per_sec=%.0f checksum=%.3f network_pps=not_measured model=%s\n",(unsigned long long)loops,(unsigned long long)elapsed,(double)loops*1000.0/(double)elapsed,(double)score,ADOS_MODEL_AVAILABLE?"advisory":"unavailable");
    return 0;
}
static int parse_limit(const char *s,uint32_t *out) {
    char *end=NULL; unsigned long n=strtoul(s,&end,10); if(!s[0]||!end||*end||n<1||n>1000000) return 0; *out=(uint32_t)n; return 1;
}
static int parse_parent_pid(const char *s,DWORD *out) {
    char *end=NULL; unsigned long long n=strtoull(s,&end,10);
    if(!s[0]||!end||*end||n<1||n>0xffffffffULL) return 0; *out=(DWORD)n; return 1;
}
int main(int argc,char **argv) {
    int observe=0,check=0,self=0,bench=0,status=0,stop=0; DWORD seconds=0,parent_pid=0;
    for(int i=1;i<argc;i++) {
        if(!strcmp(argv[i],"--observe")) observe=1;
        else if(!strcmp(argv[i],"--check")) check=1;
        else if(!strcmp(argv[i],"--self-test")) self=1;
        else if(!strcmp(argv[i],"--benchmark")) bench=1;
        else if(!strcmp(argv[i],"--status")) status=1;
        else if(!strcmp(argv[i],"--stop")) stop=1;
        else if(!strcmp(argv[i],"--parent-pid") && i+1<argc) { if(!parse_parent_pid(argv[++i],&parent_pid)) { fprintf(stderr,"invalid --parent-pid\n"); return 2; } }
        else if((!strcmp(argv[i],"--seconds") || !strcmp(argv[i],"--syn-limit") || !strcmp(argv[i],"--udp-limit") || !strcmp(argv[i],"--global-syn-limit") || !strcmp(argv[i],"--global-udp-limit")) && i+1<argc) {
            const char *opt=argv[i++],*val=argv[i]; uint32_t v=0;
            if(!strcmp(opt,"--seconds")) { if(!parse_limit(val,&v)||v>86400) { fprintf(stderr,"invalid --seconds\n");return 2;} seconds=v; }
            else if(!parse_limit(val,&v)) { fprintf(stderr,"invalid limit\n");return 2; }
            else if(!strcmp(opt,"--syn-limit")) g_syn_limit=v; else if(!strcmp(opt,"--udp-limit")) g_udp_limit=v;
            else if(!strcmp(opt,"--global-syn-limit")) g_global_syn_limit=v; else g_global_udp_limit=v;
        } else { fprintf(stderr,"usage: ados.exe [--observe|--check|--self-test|--benchmark|--status|--stop|--parent-pid N|--seconds N|--syn-limit N|--udp-limit N|--global-syn-limit N|--global-udp-limit N]\n"); return 2; }
    }
    if(self) return self_test(); if(bench) return benchmark(); if(status) return status_cmd();
    if(stop) { HANDLE e=OpenEventW(EVENT_MODIFY_STATE,FALSE,STOP_EVENT_NAME); if(!e) { DWORD err=GetLastError(); if(err==ERROR_FILE_NOT_FOUND) { puts("state=stopped\nreason=runtime event absent");return 0; }
            fprintf(stderr,"state=unknown\nreason=stop event open failed error=%lu\n",err);return 2; }
        if(!SetEvent(e)) { DWORD err=GetLastError(); CloseHandle(e); fprintf(stderr,"stop_request_failed=%lu\n",err); return 2; }
        CloseHandle(e); puts("stop_requested=1");return 0; }
    if(check) { HMODULE h=load_dll(); if(!h) { fprintf(stderr,"check=failed dependency=WinDivert.dll error=%lu\n",GetLastError());return 2;} FreeLibrary(h);printf("check=passed model=%s model_enforcement=disabled driver_open=not_attempted\n",ADOS_MODEL_AVAILABLE?"advisory":"unavailable");return 0; }
    return run_loop(observe,seconds,parent_pid);
}
