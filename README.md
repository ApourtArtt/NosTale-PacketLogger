# NtPacketLogger
PacketLogger for NosTale that (currently) works on every server (GF, HK, private servers). In the future, except it to not be working on non-amateur private server.
It is not injection based, it is using [pcap](https://fr.wikipedia.org/wiki/Pcap) under the hood.

# How does it work ?
The packetlogger requires two informations : a port and a [network interface](https://wiki.wireshark.org/CaptureSetup/NetworkInterfaces).
It then captures packet, use NosTale cryptography to decrypt/encrypt packet.
Even though pcap was not originally built to send packet, it is supported by some libraries. I am using one that supports it, so it is possible to send packet with this PoC.

# Why did I do this ?
I saw some people were really interested in this project : https://www.elitepvpers.com/forum/nostale/4901498-new-kind-packetlogger-give-some-opinions.html \
But I __guess__ it's abandonned, since it's something doable in a really short time (the logic part took me less than an hour)

# Can I do everything I am doing with an injected packetlogger ?
Kind of. There are some limitations :
- You need to have the port you want to sniff in.
- You need the encryption key to decode world client to server packet (-> it requires to select the channel with the world port set, and the world checkbox checked)
- You can only send a single packet, since the [ACK and SEQ](https://datatracker.ietf.org/doc/html/rfc793#page-15) will then be unsynchronized.

# How can I avoid players using it on my server ?
There are two easy things you can do :
1) Change the cryptography
2) Check for the packet identifier (the first "word" coming from clients). Indeed, this software does not have access to the in-game memory, it means that if the client sends a packet to your server with this software, you will receive twice the same packet ID. Check for it.

# Note :
For now, sending/receiving isn't supported. What is missing is the crafting of a TCP packet header.
