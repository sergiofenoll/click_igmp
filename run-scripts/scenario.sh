#! /bin/bash

mcaddr="224.4.4.4"

pclient21=10003
pclient22=10004
pclient31=10005
pclient32=10006

sclient21="write client21/igmp"
sclient22="write client22/igmp"
sclient31="write client31/igmp"
sclient32="write client32/igmp"

# wait a bit before starting
sleep 5


# client21 joins
echo "$sclient21.join $mcaddr" | telnet localhost $pclient21
sleep 5

# client31 joins
echo "$sclient31.join $mcaddr" | telnet localhost $pclient31
sleep 5

# client32 joins
echo "$sclient32.join $mcaddr" | telnet localhost $pclient32
sleep 5

# client21 leaves
echo "$sclient21.leave $mcaddr" | telnet localhost $pclient21
sleep 5

# client32 leaves
echo "$sclient32.leave $mcaddr" | telnet localhost $pclient32
sleep 5

# client22 joins
echo "$sclient22.join $mcaddr" | telnet localhost $pclient22
sleep 5

# client31 leaves
echo "$sclient31.leave $mcaddr" | telnet localhost $pclient31
sleep 5

# client22 leaves
echo "$sclient22.leave $mcaddr" | telnet localhost $pclient22
sleep 5
