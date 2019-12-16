#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include "IGMPQuerier.hh"

CLICK_DECLS

IGMPQuerier::IGMPQuerier(): _query_timer(this), _ctr(1), _s_qrv(0) {
    _multicast_state = Vector<GroupState>();
}
IGMPQuerier::~IGMPQuerier() {}
int IGMPQuerier::configure(Vector<String>& conf, ErrorHandler* errh) {

    uint8_t s   = 0;
    uint8_t qrv = 2;


    if (Args(conf, this, errh).read_mp("SOURCE", _src).read("S", s).read("QRV", qrv).complete() < 0) return -1;

    _s_qrv = ((s << 4) | qrv);
    _query_timer.initialize(this);
    _query_timer.schedule_after_msec((int) (_query_interval / 4));

    _group_membership_interval = (qrv * _query_interval) + _query_resp_interval;

    return 0;
}

Packet* IGMPQuerier::make_packet(IPAddress dst_addr = IPAddress("224.0.0.1")) {

    size_t packetsize = sizeof(click_ip) + sizeof(IP_options) + sizeof(igmp_memb_query);
    WritablePacket* p = Packet::make(packetsize);
    if (p == 0) {
        click_chatter("Failed to create packet.");
        return nullptr;
    }
    memset(p->data(), 0, p->length());
    
    // IP
    click_ip* iph = (click_ip*) p->data();
    iph->ip_v   = 4;
    iph->ip_hl  =  (sizeof(click_ip) + sizeof(IP_options)) >> 2;
    iph->ip_len = htons(p->length());
    iph->ip_id  = htons(_ctr);
    iph->ip_ttl = 1;
    iph->ip_p   = 2;
    iph->ip_src = _src;
    iph->ip_dst = dst_addr;

    // IP Option: Router Alert
    IP_options* ra = (IP_options*) (iph + 1);
    ra->type = 148;
    ra->length = 4;
    ra->value = 0;

    iph->ip_sum = 0;
    iph->ip_sum = click_in_cksum((unsigned char*) iph, sizeof(click_ip) + sizeof(IP_options));
    
    // IGMP Query
    igmp_memb_query* igmph = (igmp_memb_query*) (ra + 1);
    igmph->igmp_type             = IGMP_TYPE_MEMBERSHIP_QUERY;
    igmph->igmp_max_resp_code    = _max_resp_code;
    igmph->igmp_group_address    = dst_addr == IPAddress("224.0.0.1") ? IPAddress() : dst_addr;
    igmph->igmp_S_QRV            = _s_qrv;
    igmph->igmp_QQIC             = _max_resp_code;
    igmph->igmp_num_sources      = 0;
    igmph->igmp_checksum         = click_in_cksum((unsigned char*) igmph, sizeof(igmp_memb_query));

    // Annotations
    p->set_dst_ip_anno(IPAddress(iph->ip_dst));
    p->set_ip_header(iph, sizeof(*iph));

    return p;
}

void IGMPQuerier::run_timer(Timer* t) {

    uint interval = _query_interval;
    if (_ctr < (_s_qrv & IGMP_QRV_MASK)) {
	interval = (int) (interval / 4);
    }
    Packet* p = make_packet();
    output(0).push(p);
    _query_timer.schedule_after_msec(interval);

}

void IGMPQuerier::push(int, Packet* p) {

    WritablePacket* wp     = p->uniqueify();
    click_ip* iph          = wp->ip_header();

    // Split based on IP protocol (UDP or IGMP)
    if (iph->ip_p == 2) {
        // IGMP
        IP_options* ipo         = (IP_options*) (iph + 1);
        igmp_memb_report* igmph =  (igmp_memb_report*) (ipo + 1);

        if (igmph->igmp_num_group_rec > 0) {
            igmp_group_record* record = (igmp_group_record*) (igmph + 1);

            for (int i = 0; i < igmph->igmp_num_group_rec; i++) {

                uint8_t record_type     = record->igmp_record_type;
                uint32_t multicast_addr = record->igmp_multicast_addr;

                // Handle state changes
                if (record_type == IGMP_CHANGE_TO_EXCLUDE_MODE) {

                    // TODO: Timer-based actions

                    // Existing groups
                    bool group_exists = false;
                    for (int i = 0; i < _multicast_state.size(); i++) {
                        if (multicast_addr == _multicast_state[i].group_addr.addr()) {
                            group_exists = true;
                            break; 
                        }
                    }
                    // New group
                    if (!group_exists) {
			            GroupTimerData* timerdata = new GroupTimerData;
			            timerdata->querier = this;
			            timerdata->multicast_address = multicast_addr;
                        Timer* group_timer = new Timer(&IGMPQuerier::handleGroupTimeout, timerdata);
                        GroupState new_group = GroupState {multicast_addr, group_timer, IGMP_MODE_IS_EXCLUDE};
			            group_timer->initialize(this);
			            group_timer->schedule_after_msec(_group_membership_interval);
                        _multicast_state.push_back(new_group);
                    }
                }
                else if (record_type == IGMP_CHANGE_TO_INCLUDE_MODE) {
                    // TODO: Implement this using timers
                    // Set group timer to Last Member Query Time (seconds)
		    
                    for (auto it = _multicast_state.begin(); it !=  _multicast_state.end(); it++) {
                        if (it->group_addr == multicast_addr) {
			                uint count = (_s_qrv & IGMP_QRV_MASK) - 1;
                            it->group_timer->schedule_after_msec(igmp_code_to_ms(_max_resp_code) * count);
			                LastMemberTimerData* timerdata = new LastMemberTimerData;
			                timerdata->querier = this;
			                timerdata->multicast_address = multicast_addr;
			                timerdata->count = count;
                            Timer* leave_timer = new Timer(&IGMPQuerier::handleMemberLeave, timerdata);
			                leave_timer->initialize(this);
		 	                leave_timer->schedule_after_msec(igmp_code_to_ms(_max_resp_code));
                        }
                    }
		    

                    // Respond with Group-Specific Query
                    Packet* p = make_packet(IPAddress(multicast_addr));
                    output(0).push(p);
                }
                // Handle state reports
                else if (record_type == IGMP_MODE_IS_EXCLUDE) {
                    // Set group timer for this group to GMI
                    for (auto it = _multicast_state.begin(); it !=  _multicast_state.end(); it++) {
                        if (it->group_addr == multicast_addr) {
                            it->group_timer->schedule_after_msec(_group_membership_interval);
                        }
                    }
                }

                record++;
            }
        }        
    } else if (iph->ip_p == 17) {
        // UDP
        // Check if interface is interested in this group
        // If yes, send to output
        for (int i = 0; i < _multicast_state.size(); i++) {
            if (iph->ip_dst == _multicast_state[i].group_addr) {
                output(0).push(p);
                return;
                
            }
        }
    }
}

void IGMPQuerier::handleGroupTimeout(Timer* timer, void* data) {
    // Delete appropriate group
    GroupTimerData* timerdata = (GroupTimerData*) data;
    for (auto it = timerdata->querier->_multicast_state.begin(); it != timerdata->querier->_multicast_state.end(); it++) {
        if (it->group_addr == timerdata->multicast_address) {
            timerdata->querier->_multicast_state.erase(it);
	        delete timer;
            return;
        }
    }
}

void IGMPQuerier::handleMemberLeave(Timer* timer, void* data) {
    // Delete appropriate group
    LastMemberTimerData* timerdata = (LastMemberTimerData*) data;
    if (timerdata->count > 1) {
	click_chatter("Group specific query count: %d", timerdata->count);
        timerdata->count--;
        timer->schedule_after_msec(igmp_code_to_ms(timerdata->querier->_max_resp_code));
        // Send Group-Specific Query
        Packet* p = timerdata->querier->make_packet(timerdata->multicast_address);
        timerdata->querier->output(0).push(p);
    } else {
        delete timer;
    }
}


int igmp_code_to_ms(uint8_t code) {
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
EXPORT_ELEMENT(IGMPQuerier)
