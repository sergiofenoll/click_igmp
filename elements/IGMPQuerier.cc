#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include "IGMPQuerier.hh"

CLICK_DECLS

IGMPQuerier::IGMPQuerier(): _timer(this), _ctr(1), _s_qrv(0) {
    _multicast_state = Vector<IPAddress>();
}
IGMPQuerier::~IGMPQuerier() {}
int IGMPQuerier::configure(Vector<String>& conf, ErrorHandler* errh) {

    uint8_t s   = 0;
    uint8_t qrv = 2;


    if (Args(conf, this, errh).read_mp("SOURCE", _src).read("S", s).read("QRV", qrv).complete() < 0) return -1;

    _s_qrv = ((s << 4) | qrv);
    _timer.initialize(this);
    _timer.schedule_after_msec(_interval);

    return 0;
}

Packet* IGMPQuerier::make_packet() {
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
    iph->ip_dst = IPAddress("224.0.0.1");

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
    igmph->igmp_max_resp_code    = 69;
    igmph->igmp_group_address    = 0;
    igmph->igmp_S_QRV            = _s_qrv;
    igmph->igmp_QQIC             = 125;
    igmph->igmp_num_sources      = 0;
    igmph->igmp_checksum         = click_in_cksum((unsigned char*) igmph, sizeof(igmp_memb_query));

    // Annotations
    p->set_dst_ip_anno(IPAddress(iph->ip_dst));
    p->set_ip_header(iph, sizeof(*iph));

    return p;
}

void IGMPQuerier::run_timer(Timer* t) {

    Packet* p = make_packet();
    output(0).push(p);
    _timer.reschedule_after_msec(_interval);

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

                    // Don't duplicate groups
                    for (int i = 0; i < _multicast_state.size(); i++) {
                        if (multicast_addr == _multicast_state[i].addr()) {
                            return; 
                        }
                    }

                    // TODO: Timer-based actions
                    _multicast_state.push_back(multicast_addr);
                }

                record++;
            }
        }        
    } else if (iph->ip_p == 17) {
        // UDP
        // Check if interface is interested in this group
        // If yes, send to output
        for (int i = 0; i < _multicast_state.size(); i++) {
            if (iph->ip_dst == _multicast_state[i]) {
                output(0).push(p);
                return;
                
            }
        }
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IGMPQuerier)
