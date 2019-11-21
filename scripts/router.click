// Router with three interfaces
// The input/output configuration is as follows:
//
// Input:
//	[0]: packets received on the 192.168.1.0/24 network
//	[1]: packets received on the 192.168.2.0/24 network
//	[2]: packets received on the 192.168.3.0/24 network
//
// Output:
//	[0]: packets sent to the 192.168.1.0/24 network
//	[1]: packets sent to the 192.168.2.0/24 network
//	[2]: packets sent to the 192.168.3.0/24 network
//  [3]: packets destined for the router itself

// TODO:
// 	- Add timed queries
//  - Add leave response

elementclass Router {
	$server_address, $client1_address, $client2_address |

	// Shared IP input path and routing table
	ip :: Strip(14)
		-> CheckIPHeader
		-> rt :: StaticIPLookup(
					$server_address:ip/32 0,
					$client1_address:ip/32 0,
					$client2_address:ip/32 0,
					$server_address:ipnet 1,
					$client1_address:ipnet 2,
					$client2_address:ipnet 3);
	
	// ARP responses are copied to each ARPQuerier and the host.
	arpt :: Tee (3);
	
	// IGMP Support
	igmp0 :: IGMPQuerier($server_address);
	igmp1 :: IGMPQuerier($client1_address);
	igmp2 :: IGMPQuerier($client2_address);
	igmpt :: Tee(3);
	igmpt[0] -> Strip(14) -> igmp0; // Ethernet header is stripped to prevent double header later on
	igmpt[1] -> Strip(14) -> igmp1;
	igmpt[2] -> Strip(14) -> igmp2;

	// Input and output paths for interface 0
	input[0]
		-> HostEtherFilter($server_address)
		-> server_class :: Classifier(12/0806 20/0001, 12/0806 20/0002, -)
		-> ARPResponder($server_address)
		-> [0]output;

	server_arpq :: ARPQuerier($server_address) -> output;
	server_class[1] -> arpt[0] -> [1]server_arpq;
	server_class[2] -> Paint(1)
			//-> MarkIPHeader(14) // Necessary if we want to use IPClassifier?
			-> igmp_multicast_class0 :: IPClassifier(dst net 224.0.0.0/8, -)
			-> igmp_proto_class0 :: IPClassifier(ip proto igmp, ip proto udp, -)
			-> igmp0
			-> server_arpq
			-> [0]output;

	igmp_multicast_class0[1]
			-> ip;

	igmp_proto_class0[1]
			-> igmpt;

	igmp_proto_class0[2] -> Discard;


	// Input and output paths for interface 1
	input[1]
		-> HostEtherFilter($client1_address)
		-> client1_class :: Classifier(12/0806 20/0001, 12/0806 20/0002, -)
		-> ARPResponder($client1_address)
		-> [1]output;

	client1_arpq :: ARPQuerier($client1_address) -> [1]output;
	client1_class[1] -> arpt[1] -> [1]client1_arpq;
	client1_class[2] -> Paint(2) 
			 //-> MarkIPHeader(14)
			 -> igmp_multicast_class1 :: IPClassifier(dst net 224.0.0.0/8, -)
			 -> igmp_proto_class1 :: IPClassifier(ip proto igmp, ip proto udp, -)
			 -> igmp1
			 -> client1_arpq
			 -> [1]output;

	igmp_multicast_class1[1]
			 -> ip;

	igmp_proto_class1[1]
			-> igmpt;

	igmp_proto_class1[2] -> Discard;


	// Input and output paths for interface 2
	input[2]
		-> HostEtherFilter($client2_address)
		-> client2_class :: Classifier(12/0806 20/0001, 12/0806 20/0002, -)
		-> ARPResponder($client2_address)
		-> [2]output;

	client2_arpq :: ARPQuerier($client2_address) -> [2]output;
	client2_class[1] -> arpt[2] -> [1]client2_arpq;
	client2_class[2] -> Paint(3)
			 //-> MarkIPHeader(14)
			 -> igmp_multicast_class2 :: IPClassifier(dst net 224.0.0.0/8, -)
			 -> igmp_proto_class2 :: IPClassifier(ip proto igmp, ip proto udp, -)
		     -> igmp2
			 -> client2_arpq
			 -> [2]output;

	igmp_multicast_class2[1]
			 -> ip;

	igmp_proto_class2[1]
			-> igmpt;

	igmp_proto_class2[2] -> Discard;


	// Local delivery
	rt[0] -> [3]output
	
	// Forwarding paths per interface
	rt[1]
		-> DropBroadcasts
		-> server_paint :: PaintTee(1)
		-> server_ipgw :: IPGWOptions($server_address)
		-> FixIPSrc($server_address)
		-> server_ttl :: DecIPTTL
		-> server_frag :: IPFragmenter(1500)
		-> server_arpq;
	
	server_paint[1] -> ICMPError($server_address, redirect, host) -> rt;
	server_ipgw[1]  -> ICMPError($server_address, parameterproblem) -> rt;
	server_ttl[1]   -> ICMPError($server_address, timeexceeded) -> rt;
	server_frag[1]  -> ICMPError($server_address, unreachable, needfrag) -> rt;


	rt[2]
		-> DropBroadcasts
		-> client1_paint :: PaintTee(2)
		-> client1_ipgw :: IPGWOptions($client1_address)
		-> FixIPSrc($client1_address)
		-> client1_ttl :: DecIPTTL
		-> client1_frag :: IPFragmenter(1500)
		-> client1_arpq;
	
	client1_paint[1] -> ICMPError($client1_address, redirect, host) -> rt;
	client1_ipgw[1]  -> ICMPError($client1_address, parameterproblem) -> rt;
	client1_ttl[1]   -> ICMPError($client1_address, timeexceeded) -> rt;
	client1_frag[1]  -> ICMPError($client1_address, unreachable, needfrag) -> rt;

	
	rt[3]
		-> DropBroadcasts
		-> client2_paint :: PaintTee(2)
		-> client2_ipgw :: IPGWOptions($client2_address)
		-> FixIPSrc($client2_address)
		-> client2_ttl :: DecIPTTL
		-> client2_frag :: IPFragmenter(1500)
		-> client2_arpq;
	
	client2_paint[1] -> ICMPError($client2_address, redirect, host) -> rt;
	client2_ipgw[1]  -> ICMPError($client2_address, parameterproblem) -> rt;
	client2_ttl[1]   -> ICMPError($client2_address, timeexceeded) -> rt;
	client2_frag[1]  -> ICMPError($client2_address, unreachable, needfrag) -> rt;
}
