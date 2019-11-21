#ifndef CLICK_IGMPQuerier_HH
#define CLICK_IGMPQuerier_HH
#include <click/element.hh>
#include <click/timer.hh>
#include <clicknet/ip.h>
#include "IGMPHeaders.hh"


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
        Packet* make_packet();
        void push(int, Packet*);

    private:

        Timer     _timer;
        uint      _interval = 5000;
        uint      _ctr;
        uint8_t   _s_qrv;
        IPAddress _src;
        Vector<IPAddress> _multicast_state;
	int _id; // Testing
};


CLICK_ENDDECLS

#endif
