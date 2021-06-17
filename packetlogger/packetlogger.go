package packetlogger

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ApourtArtt/NtPacketLogger/cryptography"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/tadvi/winc"
)

type PacketLogger struct {
	// Logic
	interfaces      []pcap.Interface
	chosenInterface pcap.Interface
	pcapHandle      *pcap.Handle
	isWorld         bool

	port string
	pid  int // Should be uint16 but it would require some code change. Lazy
	key  int

	sentBuffer []byte
	rcvdBuffer []byte

	// UI
	mainWindow   *winc.Form
	teRcvdPacket *winc.MultiEdit
}

func (pl *PacketLogger) Init() {
	pl.pid = -1
	pl.key = -1
	pl.isWorld = false

	pl.mainWindow = winc.NewForm(nil)
	dock := winc.NewSimpleDock(pl.mainWindow)
	pl.mainWindow.SetLayout(dock)
	pl.mainWindow.SetSize(600, 400)
	pl.mainWindow.SetText("NosTale PacketLogger")
	pl.mainWindow.OnClose().Bind(func(e *winc.Event) {
		winc.Exit()
	})

	// Used only for docking. lPort, etc should be child of it
	top := winc.NewPanel(pl.mainWindow)
	top.SetSize(-1, 23)

	lPort := winc.NewLabel(top)
	lPort.SetText("Port")
	lPort.SetPos(4, 4)

	tePort := winc.NewEdit(top)
	tePort.OnChange().Bind(func(e *winc.Event) {
		_, err := strconv.Atoi(tePort.Text())
		if err != nil || len(tePort.Text()) == 0 {
			return
		}
		pl.port = tePort.Text()
		pl.resetLogger()
	})
	tePort.SetPos(30, 0)
	tePort.SetSize(50, 20)

	lNetInterface := winc.NewLabel(top)
	lNetInterface.SetText("Net Interface")
	lNetInterface.SetPos(84, 4)

	cbNetInterface := winc.NewComboBox(top)
	cbNetInterface.SetPos(150, 0)
	cbNetInterface.OnSelectedChange().Bind(func(e *winc.Event) {
		id := strings.Split(cbNetInterface.Text(), " (")
		if len(id) != 2 {
			return
		}
		for i := 0; i < len(pl.interfaces); i++ {
			if pl.interfaces[i].Description == id[0] && pl.interfaces[i].Name == id[1][:len(id[1])-1] {
				pl.chosenInterface = pl.interfaces[i]
				pl.pcapHandle, _ = pcap.OpenLive(pl.interfaces[i].Name, 8192, true, pcap.BlockForever) // Max NT packet length * 2
				pl.resetLogger()
				break
			}
		}
	})

	chbWorld := winc.NewCheckBox(top)
	chbWorld.SetText("World")
	chbWorld.SetPos(360, 0)
	chbWorld.OnClick().Bind(func(e *winc.Event) {
		pl.isWorld = chbWorld.Checked()
	})

	pl.teRcvdPacket = winc.NewMultiEdit(pl.mainWindow)
	dock.Dock(top, winc.Top)
	dock.Dock(pl.teRcvdPacket, winc.Fill)

	pl.interfaces, _ = pcap.FindAllDevs()
	for i := 0; i < len(pl.interfaces); i++ {
		cbNetInterface.InsertItem(i, pl.interfaces[i].Description+" ("+pl.interfaces[i].Name+")")
	}
}

func (pl *PacketLogger) Run() {
	go func() {
		var err error
		for {
			for pl.pcapHandle == nil || len(pl.port) == 0 {
				time.Sleep(500 * time.Millisecond)
			}

			packetSource := gopacket.NewPacketSource(pl.pcapHandle, pl.pcapHandle.LinkType())
			if packetSource == nil {
				continue
			}

			for packet := range packetSource.Packets() {
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer == nil {
					continue
				}
				applicationLayer := packet.ApplicationLayer()
				if applicationLayer == nil {
					continue
				}

				var packetStr string
				if !isIpInInterface(pl.chosenInterface, packet.NetworkLayer().NetworkFlow().Src().String()) {
					if !pl.isWorld {
						packetStr = string(cryptography.LoginDecryptServerPacket(applicationLayer.Payload()))
						pl.teRcvdPacket.SetText(pl.teRcvdPacket.Text() + "Rcvd: " + packetStr + "\r\n")
						fmt.Println("Rcvd: ", packetStr)
					} else {
						pl.rcvdBuffer = append(pl.rcvdBuffer, applicationLayer.Payload()...)
						for len(pl.rcvdBuffer) > 0 {
							packetStr := string(cryptography.WorldDecryptServerPacket(&pl.rcvdBuffer))
							if len(packetStr) == 0 {
								break
							}
							pl.teRcvdPacket.SetText(pl.teRcvdPacket.Text() + "Rcvd: " + packetStr + "\r\n")
							fmt.Println("Rcvd: ", packetStr)
						}
					}
				} else {
					if !pl.isWorld {
						packetStr = string(cryptography.LoginDecryptClientPacket(applicationLayer.Payload()))
						pl.teRcvdPacket.SetText(pl.teRcvdPacket.Text() + "Sent: " + packetStr + "\r\n")
						fmt.Println("Sent: ", packetStr)
					} else {
						pl.sentBuffer = append(pl.sentBuffer, applicationLayer.Payload()...)

						for len(pl.sentBuffer) > 0 {
							packetStr := string(cryptography.WorldDecryptClientPacket(&pl.sentBuffer, pl.key, pl.key == -1))
							fmt.Println("> ", packetStr)
							if len(packetStr) == 0 {
								break
							}
							pl.teRcvdPacket.SetText(pl.teRcvdPacket.Text() + "Sent: " + packetStr + "\r\n")
							fmt.Println("Sent: ", packetStr)
							split := strings.Split(packetStr, " ")

							if len(split) < 2 {
								continue
							}

							tmpPid := pl.pid + 1
							pl.pid, err = strconv.Atoi(split[0])
							if err != nil {
								pl.pid = tmpPid
							}

							if pl.key == -1 && len(split) == 2 {
								fmt.Println("OK")
								pl.key, err = strconv.Atoi(split[1])
								if err != nil {
									pl.key = -1 // because it is 0 if err != nil
									fmt.Println("Failed retrieving encryptionKey, retry on next packet")
								}
							}
						}
					}
				}
			}
		}
	}()
	pl.mainWindow.Center()
	pl.mainWindow.Show()
	winc.RunMainLoop()
}

func (pl *PacketLogger) resetLogger() {
	if pl.pcapHandle == nil || len(pl.port) == 0 {
		return
	}
	pl.pcapHandle.SetBPFFilter("tcp and port " + pl.port)
}

func isIpInInterface(networkInterface pcap.Interface, ip string) bool {
	for i := 0; i < len(networkInterface.Addresses); i++ {
		if networkInterface.Addresses[i].IP.String() == ip {
			return true
		}
	}
	return false
}
