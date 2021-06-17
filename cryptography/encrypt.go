package cryptography

import "fmt"

func LoginEncrypt(packet []byte) []byte {
	return []byte{} // Will it ever be used ?
}

func worldClientXor(packet []byte, session int, isFirstPacket bool) []byte {
	var output []byte
	sType := -1

	if !isFirstPacket {
		sType = (session >> 6) & 3
	}

	key := session & 0xFF

	for i := 0; i < len(packet); i++ {
		if sType == 0 {
			output = append(output, (packet[i]+byte(key)+0x40)&0xFF)
		} else if sType == 1 {
			output = append(output, (packet[i]-byte(key)-0x40)&0xFF)
		} else if sType == 2 {
			output = append(output, ((packet[i]^0xC3)+byte(key)+0x40)&0xFF)
		} else if sType == 3 {
			output = append(output, ((packet[i]^0xC3)-byte(key)-0x40)&0xFF)
		} else {
			output = append(output, (packet[i]+0xF)&0xFF)
		}
	}

	return output
}

func WorldEncrypt(packet, pid []byte, session int, isFirstPacket bool) []byte {
	pid = append(pid, ' ')
	pid = append(pid, packet...)
	fmt.Println(string(pid))

	return worldClientXor(pack(pid, table_0xFF), session, isFirstPacket)
}
