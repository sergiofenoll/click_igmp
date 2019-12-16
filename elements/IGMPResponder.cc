#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include "IGMPResponder.hh"

CLICK_DECLS

IGMPResponder::IGMPResponder(): _response_timer(this), _ctr(1), _num_group_records(0) {}
IGMPResponder::~IGMPResponder() {}
int IGMPResponder::configure(Vector<String>& conf, ErrorHandler* errh) {

    if (Args(conf, this, errh).read_mp("SOURCE", _src).complete() < 0) return -1;
    
    _response_timer.initialize(this);

    return 0;
}

Packet* IGMPResponder::make_packet(Vector<igmp_group_record> records = Vector<igmp_group_record>()) {
    size_t packetsize = sizeof(click_ip) + sizeof(IP_options) + sizeof(igmp_memb_report)
                        + records.size() * sizeof(igmp_group_record);
    WritablePacket* p = Packet::make(packetsize);
    if (p == 0) {
        click_chatter("Failed to create packet.");
        return nullptr;
    }
    memset(p->data(), 0, p->length());

    // IP
    click_ip* iph = (click_ip*) p->data();
    iph->ip_v   = 4;
    iph->ip_hl  = (sizeof(click_ip) + sizeof(IP_options)) >> 2;
    iph->ip_len = htons(p->length());
    iph->ip_id  = htons(_ctr);
    iph->ip_ttl = 1;
    iph->ip_p   = 2;
    iph->ip_src = _src;
    iph->ip_dst = IPAddress("224.0.0.22");

    // IP Option: Router Alert
    IP_options* ra = (IP_options*) (iph + 1);
    ra->type = 148;
    ra->length = 4;
    ra->value = 0;

 	iph->ip_sum = 0;
    iph->ip_sum = click_in_cksum((unsigned char*) iph, sizeof(click_ip) + sizeof(IP_options));
    
    // IGMP Report
    igmp_memb_report* igmph 	 = (igmp_memb_report*) (ra + 1);
    igmph->igmp_type             = IGMP_TYPE_MEMBERSHIP_REPORT;
    igmph->igmp_num_group_rec    = htons(records.size());

    // Records
    igmp_group_record* record = (igmp_group_record*) (igmph + 1);
    for (int i = 0; i < records.size(); i++) {

        record->igmp_record_type    = records[i].igmp_record_type;
        record->igmp_aux_data       = records[i].igmp_aux_data;
        record->igmp_num_sources    = records[i].igmp_num_sources;
        record->igmp_multicast_addr = records[i].igmp_multicast_addr;

        record++;
    }

    igmph->igmp_checksum = click_in_cksum((unsigned char*) igmph, sizeof(igmp_memb_report) + sizeof(igmp_group_record) * records.size());
   
    // Annotations
    p->set_dst_ip_anno(IPAddress(iph->ip_dst));
    p->set_ip_header(iph, sizeof(*iph));

    return p;
}

igmp_group_record IGMPResponder::make_record(IPAddress addr, uint8_t type) {
	igmp_group_record record   = igmp_group_record();
    record.igmp_record_type    = type;
    record.igmp_aux_data       = 0;
    record.igmp_num_sources    = 0;
    record.igmp_multicast_addr = addr;
	return record;
}

void IGMPResponder::push(int, Packet* p) {
    // Accepts Query messages and starts appropriate timer if necessary.
    // Also accepts UDP messages and lets them through if appropriate.
    /* 
        TODO:
             - Calculate timer from max_resp_code 
             - Start timer
    */

    WritablePacket* wp     = p->uniqueify();
    click_ip* iph          = wp->ip_header();
    IP_options* ipo        = (IP_options*) (iph + 1);

    if (iph->ip_p == 17) {
        // UDP Packets
        // Check if listening to multicast group, if yes, let packet through
        for (int i = 0; i < _multicast_state.size(); i++) {
            if (iph->ip_dst == _multicast_state[i]) {
                output(0).push(p);
                return;
            }
        }        
    }
    else if (iph->ip_p == 2) {
        // IGMP Packets
        igmp_memb_query* igmph =  (igmp_memb_query*) (ipo + 1);

        // General queries
        // TODO: make this timed
        Vector<igmp_group_record> records = Vector<igmp_group_record>();
        if (igmph->igmp_group_address == 0 && igmph->igmp_num_sources == 0) {
                // Only send response if state is non-empty
                if (!_multicast_state.empty()) {
                    for (int i = 0; i < _multicast_state.size(); i++) {
                        igmp_group_record record;
                        record.igmp_record_type    = IGMP_MODE_IS_EXCLUDE;
                        record.igmp_aux_data       = 0;
                        record.igmp_num_sources    = 0; // 0 because sources aren't supported by this implementation
                        record.igmp_multicast_addr = _multicast_state[i];
                        records.push_back(record);
                    }
                }
        }

        // Group-specific queries
        if (igmph->igmp_group_address > 0) {
            
            bool listening = false;
            for (int i = 0; i < _multicast_state.size(); i++) {
                
                if (_multicast_state[i] == igmph->igmp_group_address) {
                    igmp_group_record record;
                    record.igmp_record_type    = IGMP_MODE_IS_EXCLUDE;
                    record.igmp_aux_data       = 0;
                    record.igmp_num_sources    = 0; // 0 because sources aren't supported by this implementation
                    record.igmp_multicast_addr = _multicast_state[i];
                    records.push_back(record);
                    listening = true;
                    break;
                }
            }
            
            if (!listening) {
                for (auto it = _leaving_state.begin(); it != _leaving_state.end(); it++) {
                    if (it->group_addr == igmph->igmp_group_address) {
                        if (it->count < 0) {
                            it->count = (igmph->igmp_S_QRV & IGMP_QRV_MASK) - 1;
                        } else if (it->count == 0) {
                            _leaving_state.erase(it);
                            break;
                        }
                        
                        it->count--;
                        LeaveTimerData* timerdata = new LeaveTimerData;
                        timerdata->responder = this;
                        timerdata->group_addr = it->group_addr;
                        Timer* leave_timer = new Timer(&IGMPResponder::handleGroupLeave, timerdata);
                        leave_timer->initialize(this);
                        uint time_to_send = click_random(0, igmp_code_to_ms2(igmph->igmp_max_resp_code));
                        leave_timer->schedule_after_msec(time_to_send);
                    }
               }
            }
            
        }

        if (records.size() > 0 and !_response_timer.scheduled()) {
            Packet* response = make_packet(records);
            uint time_to_send = click_random(0, igmp_code_to_ms2(igmph->igmp_max_resp_code));
            _response_timer.schedule_after_msec(time_to_send);
            _pending_response = response;
            _ctr++;
        }
    }
}

int IGMPResponder::handle_join(const String &conf, Element* e, void* thunk, ErrorHandler* errh) {
    IGMPResponder* elem = (IGMPResponder*) e;
    Vector<String> vconf;
    cp_argvec(conf, vconf);

    IPAddress group_addr;

    if(Args(vconf, elem, errh).read_mp("GROUP", group_addr).complete() < 0)
        return -1;

    for (int i = 0; i < elem->_multicast_state.size(); i++) {
        if (elem->_multicast_state[i] == group_addr) {
            click_chatter("[WARNING] Tried to join a group that has already been joined.");
            return -1;
        }
    }

    igmp_group_record r = elem->make_record(group_addr, IGMP_CHANGE_TO_EXCLUDE_MODE);
    Packet* p           = elem->make_packet(Vector<igmp_group_record>(1, r));
    elem->output(0).push(p);

    elem->_multicast_state.push_back(group_addr);

    return 0;
} 

int IGMPResponder::handle_leave(const String &conf, Element* e, void* thunk, ErrorHandler* errh) {
    IGMPResponder* elem = (IGMPResponder*) e;
    Vector<String> vconf;
    cp_argvec(conf, vconf);

    IPAddress group_addr;

    if(Args(vconf, elem, errh).read_mp("GROUP", group_addr).complete() < 0)
        return -1;

    bool found = false;
    for (auto it = elem->_multicast_state.begin(); it != elem->_multicast_state.end(); it++) {
        if (*it == group_addr) {
            elem->_multicast_state.erase(it);
            found = true;            
            break;
        }
    }
    if (!found) {
        click_chatter("[WARNING] Tried to leave a group that hadn't been joined.");
        return -1;
    }

    igmp_group_record r = elem->make_record(group_addr, IGMP_CHANGE_TO_INCLUDE_MODE);
    Packet* p           = elem->make_packet(Vector<igmp_group_record>(1, r));
    elem->output(0).push(p);
    
    LeavingState l = LeavingState {group_addr, p, -1};
    elem->_leaving_state.push_back(l);

    return 0;
}

void IGMPResponder::add_handlers() {
	add_write_handler("join",  &handle_join,  (void*)0);
    add_write_handler("leave", &handle_leave, (void*)0);
}

void IGMPResponder::run_timer(Timer* timer) {
    // Send pending packet
    if (_pending_response) {
        output(0).push(_pending_response);
        _pending_response = nullptr;
    }
}

void IGMPResponder::handleGroupLeave(Timer* timer, void* data) {
    LeaveTimerData* timerdata = (LeaveTimerData*) data;
    igmp_group_record r = timerdata->responder->make_record(timerdata->group_addr, IGMP_CHANGE_TO_INCLUDE_MODE);
    Packet* p           = timerdata->responder->make_packet(Vector<igmp_group_record>(1, r));
    timerdata->responder->output(0).push(p);
    delete timer;
}

int igmp_code_to_ms2(uint8_t code) {
   /* Returns time in milliseconds from given code. Used for Max Resp Time & QQIC. */
   if (code < 128) {
	return code * 100;
   }
   else {
	uint8_t mant = (code & 0x10);
	uint8_t exp  = (code >> 4) & 0x8;
	return ((mant | 0x10) << (exp + 3)) * 100;
   }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IGMPResponder)
