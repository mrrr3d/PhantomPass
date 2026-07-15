#ifndef ns_udp_r2p2_h
#define ns_udp_r2p2_h

#include "udp.h"
#include "r2p2-generic.h"
#include "r2p2-hdr.h"
#include "msg-tracer.h"
#include <iostream>
#include <string>

#define FID_TO_REQID -1
#define DEFAULT_PRIO 7
#define NO_PRIO -1
#define NO_CURRENT_TTL -1
#define NO_SRC_REPLACEMENT -1
#define ECN_CAPABLE 1

class R2p2Transport;

class R2p2Agent : public UdpAgent
{
public:
    R2p2Agent();
    R2p2Agent(packet_t);
    // hack. if fid==-1, set fid to r2p2 req_id,
    // prio 0-7 -> 0 = high priority
    // ECN capable if ecn_capable==1, else not.
    void sendmsg(int nbytes, hdr_r2p2 &r2p2_hdr, MsgTracerLogs &&logs, int fid = FID_TO_REQID, int prio = NO_PRIO, int current_ttl = NO_CURRENT_TTL, int32_t source_addr = NO_SRC_REPLACEMENT, int ecn_capable = ECN_CAPABLE, const char *flags = 0);
    void recv(Packet *, Handler *);

    void attach_r2p2_transport(R2p2Transport *r2p2_transport);

private:
    R2p2Transport *r2p2_layer_;
};

#endif