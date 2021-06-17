package cryptography

// https://github.com/morsisko/NosCrypto

import (
	"bytes"
	"math"
)

var table_0xAA = []byte{0x00, 0x20, 0x2D, 0x2E, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x0A, 0x00}
var table_0xFF = []byte{0x00, 0x20, 0x2D, 0x2E, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xFF, 0x00}

func getMaskPart(ch byte, charset []byte) bool {
	if ch == 0 {
		return false
	}
	for i := 0; i < len(charset); i++ {
		if charset[i] == ch {
			return true
		}
	}
	return false
}

func getMask(packet, charset []byte) []bool {
	var output []bool
	for i := 0; i < len(packet); i++ {
		if packet[i] == 0 {
			break
		}
		output = append(output, getMaskPart(packet[i], charset))
	}
	return output
}

func calcLenOfMask(start int, mask []bool, value bool) int {
	currentLen := 0
	for i := start; i < len(mask); i++ {
		if mask[i] == value {
			currentLen++
		} else {
			break
		}
	}
	return currentLen
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func pack(packet, charsToPack []byte) []byte {
	var output []byte
	mask := getMask(packet, charsToPack)
	pos := 0

	for len(mask) > pos {
		currentChunkLen := calcLenOfMask(pos, mask, false)
		for i := 0; i < currentChunkLen; i++ {
			if pos > len(mask) {
				break
			}
			if i%0x7E == 0 {
				output = append(output, byte(min(currentChunkLen-i, 0x7E)))
			}
			output = append(output, packet[pos]^0xFF)
			pos++
		}
		currentChunkLen = calcLenOfMask(pos, mask, true)
		for i := 0; i < currentChunkLen; i++ {
			if pos > len(mask) {
				break
			}
			if i%0x7E == 0 {
				output = append(output, byte(min(currentChunkLen-i, 0x7E)|0x80))
			}
			currentValue := bytes.IndexByte(charsToPack, packet[pos])
			if i%2 == 0 {
				output = append(output, byte(currentValue)<<4)
			} else {
				output[len(output)-1] |= byte(currentValue)
			}
			pos++
		}
	}
	output = append(output, 0xFF)
	return output
}

func unpack(packet, charsToUnpack []byte) []byte {
	var output []byte

	for pos := 0; len(packet) > pos; {
		if packet[pos] == 0xFF {
			break
		}

		currentChunkLen := packet[pos] & 0x7F
		isPacked := packet[pos]&0x80 != 0
		pos++

		if isPacked {
			for i := 0; i < int(math.Ceil(float64(currentChunkLen)/2)); i++ {
				if pos >= len(packet) {
					break
				}

				twoChars := packet[pos]
				pos++

				leftChar := twoChars >> 4
				output = append(output, charsToUnpack[leftChar])

				rightChar := twoChars & 0xF
				if rightChar == 0 {
					break
				}
				output = append(output, charsToUnpack[rightChar])
			}
		} else {
			for i := 0; i < int(currentChunkLen); i++ {
				if pos >= len(packet) {
					break
				}

				output = append(output, packet[pos]^0xFF)
				pos++
			}
		}
	}

	return output
}

func unpackServ(packet *[]byte, charsToUnpack []byte) []byte {
	var output []byte
	pos := 0

	valtest := 0
	passed := false

	for len(*packet) > pos {
		if (*packet)[pos] == 0xFF {
			*packet = (*packet)[pos+1:]
			passed = true
			break
		}

		currentChunkLen := (*packet)[pos] & 0x7F
		isPacked := (*packet)[pos]&0x80 != 0
		pos++

		if isPacked {
			for i := 0; i < int(math.Ceil(float64(currentChunkLen)/2)); i++ {
				if pos >= len((*packet)) {
					break
				}

				twoChars := (*packet)[pos]
				pos++

				leftChar := twoChars >> 4
				output = append(output, charsToUnpack[leftChar])

				rightChar := twoChars & 0xF
				if rightChar == 0 {
					break
				}
				output = append(output, charsToUnpack[rightChar])
			}
		} else {
			for i := 0; i < int(currentChunkLen); i++ {
				if pos >= len((*packet)) {
					break
				}

				output = append(output, (*packet)[pos]^0xFF)
				pos++
			}
			valtest += int(currentChunkLen)
		}
	}

	if !passed {
		return []byte{}
	}

	return output
}
