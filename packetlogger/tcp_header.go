package packetlogger

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TcpHeaderBuilder struct {
	ethSent           layers.Ethernet
	dot1qSent         layers.Dot1Q
	ip4Sent           layers.IPv4 // ip4.version << 4 + ihl
	ip6Sent           layers.IPv6
	ip6extensionsSent layers.IPv6ExtensionSkipper
	tcpSent           layers.TCP

	ethRcvd           layers.Ethernet
	dot1qRcvd         layers.Dot1Q
	ip4Rcvd           layers.IPv4 // ip4.version << 4 + ihl
	ip6Rcvd           layers.IPv6
	ip6extensionsRcvd layers.IPv6ExtensionSkipper
	tcpRcvd           layers.TCP
}

func (builder *TcpHeaderBuilder) ParseReceivedPacket(packet gopacket.Packet) {
	var payload gopacket.Payload
	decoded := make([]gopacket.LayerType, 0, 4)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&builder.ethRcvd, &builder.dot1qRcvd, &builder.ip4Rcvd, &builder.ip6Rcvd, &builder.ip6extensionsRcvd, &builder.tcpRcvd, &payload)

	err := parser.DecodeLayers(packet.Data(), &decoded)
	if err != nil {
		fmt.Println("ERR1 : ", err)
	}
}

func (builder *TcpHeaderBuilder) ParseSentPacket(packet gopacket.Packet) {
	var payload gopacket.Payload
	decoded := make([]gopacket.LayerType, 0, 4)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&builder.ethSent, &builder.dot1qSent, &builder.ip4Sent, &builder.ip6Sent, &builder.ip6extensionsSent, &builder.tcpSent, &payload)

	err := parser.DecodeLayers(packet.Data(), &decoded)
	if err != nil {
		fmt.Println("ERR1 : ", err)
	}
}

func (builder *TcpHeaderBuilder) FormatPacket(data []byte, asSent bool) []byte {
	if asSent {
		ethLayer := builder.ethSent

		ipLayer := builder.ip4Sent
		ipLayer.Id++

		tcpLayer := builder.tcpSent
		tcpLayer.Seq = builder.tcpRcvd.Ack
		tcpLayer.Ack = builder.tcpRcvd.Seq + 1

		tcpLayer.SetNetworkLayerForChecksum(&ipLayer)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}

		err := gopacket.SerializeLayers(buf, opts,
			&ethLayer,
			&ipLayer,
			&tcpLayer,
			gopacket.Payload(data))

		fmt.Println("ERR2 : ", err)

		return buf.Bytes()
	} else {

	}
	return []byte{}
}
