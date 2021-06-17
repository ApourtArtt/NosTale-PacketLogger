package cryptography

// LoginDecryptServerPacket decrypts login packet received (server -> client) ex: NsTeST
func LoginDecryptServerPacket(packet []byte) []byte {
	var output []byte
	for i := 0; i < len(packet); i++ {
		output = append(output, (packet[i] - 0xF))
	}
	return output
}

// LoginDecryptClientPacket decrypts login packet sent (client -> server) ex: NoS0577
// this is not intended to be used for actually sending packet, see LoginEncrypt for this.
func LoginDecryptClientPacket(packet []byte) []byte {
	var output []byte
	for i := 0; i < len(packet); i++ {
		v := (packet[i] - 0xF) ^ 0xC3
		output = append(output, v&0xFF)
	}
	return output
}

// WorldDecryptServerPacket decrypts world packet received (server -> client) ex: mv
func WorldDecryptServerPacket(packet *[]byte) []byte {
	return unpackServ(packet, table_0xAA)
}

func worldServerXor(packet *[]byte, session int, isFirstPacket bool) []byte {
	var output []byte
	sType := -1

	if !isFirstPacket {
		sType = (session >> 6) & 3
	}

	key := session & 0xFF

	for i := 0; i < len(*packet); i++ {
		var b byte
		if sType == 0 {
			b = ((*packet)[i] - byte(key) - 0x40) & 0xFF
		} else if sType == 1 {
			b = ((*packet)[i] + byte(key) + 0x40) & 0xFF
		} else if sType == 2 {
			b = (((*packet)[i] - byte(key) - 0x40) ^ 0xC3) & 0xFF
		} else if sType == 3 {
			b = (((*packet)[i] + byte(key) + 0x40) ^ 0xC3) & 0xFF
		} else {
			b = ((*packet)[i] - 0xF) & 0xFF
		}
		output = append(output, b)
		if b == 0xFF {
			if i+1 <= len(*packet) { // Should not happen since 1 byte input = 1 byte output, but well, we never know.
				*packet = (*packet)[i+1:]
			}
			break
		}
	}

	return output
}

// WorldDecryptClientPacket decrypts world packet sent (client -> server) ex: walk
// this is not intended to be used for actually sending packet, see WorldEncrypt for this.
func WorldDecryptClientPacket(packet *[]byte, session int, isFirstPacket bool) []byte {
	data := worldServerXor(packet, session, isFirstPacket)
	return unpack(data, table_0xFF)
}
