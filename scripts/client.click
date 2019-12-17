// Output configuration: 
//
// Packets for the network are put on output 0
// Packets for the host are put on output 1

elementclass Client {
	$address, $gateway |

	ip :: Strip(14)
		-> CheckIPHeader()
		-> rt :: StaticIPLookup(
					$address:ip/32 0,
					$address:ipnet 0,
					0.0.0.0/0.0.0.0 $gateway 1,
					224.0.0.0/8 2)
		-> [1]output;
	
	rt[1]	
		-> IPPrint
		-> DropBroadcasts
		-> ipgw :: IPGWOptions($address)
		-> FixIPSrc($address)
		-> ttl :: DecIPTTL
		-> frag :: IPFragmenter(1500)
		-> arpq :: ARPQuerier($address)
		-> output;

	ipgw[1] -> ICMPError($address, parameterproblem) -> output;
	ttl[1]  -> ICMPError($address, timeexceeded) -> output;
	frag[1] -> ICMPError($address, unreachable, needfrag) -> output;

	rt[2]
		// Multicast packets
		-> igmp_class :: IPClassifier(ip proto igmp or ip proto udp, -)
		-> igmp :: IGMPResponder($address)
		-> igmp_resp_class :: IPClassifier(ip proto igmp, ip proto udp)
		-> arpq;
		//-> [0]output; (reduntant because of rt[1])
		
	igmp_resp_class[1]
	    -> [1]output;

	igmp_class[1]
		// Misc multicast
		-> Discard;
	
	// Incoming Packets
	input
		-> HostEtherFilter($address)
		-> in_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800) // Queries, response, data
		-> arp_res :: ARPResponder($address) // Queries
		-> output;

	in_cl[1] -> [1]arpq; // Response
	in_cl[2] -> ip; // Data
}


