#include "IGMPHeaders.hh"

CLICK_DECLS

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
