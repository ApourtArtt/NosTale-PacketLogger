package main

import (
	pl "github.com/ApourtArtt/NtPacketLogger/packetlogger"
)

func main() {

	packetlogger := pl.PacketLogger{}
	packetlogger.Init()
	packetlogger.Run()
}
