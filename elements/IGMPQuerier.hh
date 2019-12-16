#ifndef CLICK_IGMPQuerier_HH
#define CLICK_IGMPQuerier_HH
#include <click/element.hh>
#include <click/timer.hh>
#include <clicknet/ip.h>
#include "IGMPHeaders.hh"


/*
    IGMP Querier - Router side IGMP component.
    Handles querying and forwarding of multicast UDP packets.
    All time values should be in milliseconds.
*/


struct GroupState {
    IPAddress group_addr;
    Timer* group_timer;
    int filter_mode;
};


CLICK_DECLS

class IGMPQuerier : public Element {
    public:

        IGMPQuerier();
        ~IGMPQuerier();

        const char *class_name() const {return "IGMPQuerier";}
        const char *port_count() const {return "1/1";}
        const char *processing() const {return PUSH;}
        int configure(Vector<String>&, ErrorHandler*);
        void run_timer(Timer*);
        Packet* make_packet(IPAddress);
        void push(int, Packet*);

    private:

	struct GroupTimerData {
            IGMPQuerier* querier;
            IPAddress multicast_address;
        };

	struct LastMemberTimerData {
	   IGMPQuerier* querier;
	   IPAddress multicast_address;
	   uint count;
	};

        static void handleGroupTimeout(Timer*, void*);
	static void handleMemberLeave(Timer*, void*);

        Timer     _query_timer;
        uint      _query_interval = 5000;//125000;
        uint      _query_resp_interval = 1000;//10000;
        uint      _group_membership_interval;
	uint      _max_resp_code = 10;
        uint      _ctr;
        uint8_t   _s_qrv;
        IPAddress _src;
        Vector<GroupState> _multicast_state;
};

int igmp_code_to_ms(uint8_t code);

CLICK_ENDDECLS

#endif
