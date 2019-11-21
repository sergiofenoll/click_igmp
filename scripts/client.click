// Output configuration: 
//
// Packets for the network are put on output 0
// Packets for the host are put on output 1

elementclass Client {
	$address, $gateway |

	ip :: Strip(14)
		-> CheckIPHeader()
		-> rt :: StaticIPLookup(
					224.0.0.1 0,
					$address:ip/32 0,
					$address:ipnet 0,
					0.0.0.0/0.0.0.0 $gateway 1)
		-> igmp_class :: IPClassifier(ip proto igmp, -) // General/Group-specific query, non-igmp
	
	rt[1]
		-> DropBroadcasts
		-> ipgw :: IPGWOptions($address)
		-> FixIPSrc($address)
		-> ttl :: DecIPTTL
		-> frag :: IPFragmenter(1500)
		-> arpq :: ARPQuerier($address)
		-> output;

	igmp_class[0]
		// IGMP Queries
		-> igmp :: IGMPResponder($address)
		-> arpq
		-> [0]output; 

	igmp_class[1]
		// Non-IGMP packets
		-> [1]output;

	ipgw[1] -> ICMPError($address, parameterproblem) -> output;
	ttl[1]  -> ICMPError($address, timeexceeded) -> output;
	frag[1] -> ICMPError($address, unreachable, needfrag) -> output;
	
	// Incoming Packets
	input
		-> HostEtherFilter($address)
		-> in_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800) // Queries, response, data
		-> arp_res :: ARPResponder($address) // Queries
		-> output;

	in_cl[1] -> [1]arpq; // Response
	in_cl[2] -> ip; // Data
}


