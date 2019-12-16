#ifndef CLICK_IGMPResponder_HH
#define CLICK_IGMPResponder_HH
#include <click/element.hh>
#include <click/timer.hh>
#include <clicknet/ip.h>
#include "IGMPHeaders.hh"


CLICK_DECLS

class IGMPResponder : public Element {
    public:
        IGMPResponder();
        ~IGMPResponder();

	    struct LeaveTimerData {
	        IGMPResponder* responder;
	        IPAddress group_addr;
	    };
	    
	    struct LeavingState {
            IPAddress group_addr;
	        Packet* packet;
	        int count;
	    };

        const char *class_name() const {return "IGMPResponder";}
        const char *port_count() const {return "1/1";}
        const char *processing() const {return PUSH;}
        int configure(Vector<String>&, ErrorHandler*);
        void run_timer(Timer*);
        Packet* make_packet(Vector<igmp_group_record>);
        void push(int, Packet*);

        // Handlers
        static int handle_join(const String &conf, Element* e, void* thunk, ErrorHandler* errh);
        static int handle_leave(const String &conf, Element* e, void* thunk, ErrorHandler* errh);
        void add_handlers();

    private:
    
        static void handleGroupLeave(Timer*, void*);
	    igmp_group_record make_record(IPAddress, uint8_t);
	    
	    Timer    _response_timer;
	    Packet*   _pending_response;
        uint      _ctr;
        uint      _num_group_records;
        IPAddress _src;
        Vector<IPAddress> _multicast_state;
        Vector<LeavingState> _leaving_state;
};

int igmp_code_to_ms2(uint8_t code);

CLICK_ENDDECLS

#endif
