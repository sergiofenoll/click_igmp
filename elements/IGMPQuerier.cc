#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include "IGMPQuerier.hh"

CLICK_DECLS

IGMPQuerier::IGMPQuerier(): _timer(this), _ctr(1), _s_qrv(0) {}
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
    push(0, make_packet());
    _timer.reschedule_after_msec(_interval);

}

void IGMPQuerier::push(int, Packet* p) {
    _ctr++;
    output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IGMPQuerier)
