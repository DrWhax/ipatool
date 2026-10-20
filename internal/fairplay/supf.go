package fairplay

import (
	"encoding/binary"
	"fmt"
)

type supfArchitecture struct {
	cpuType, cpuSubtype uint32
	records             [][32]byte
}

type supf struct {
	architectures []supfArchitecture
}

func parseSUPF(blob []byte) (supf, error) {
	var result supf
	if len(blob) < 12 {
		return result, fmt.Errorf("SUPF is truncated")
	}
	variant := blob[0]
	if variant != 3 && variant != 5 {
		return result, fmt.Errorf("unsupported SUPF variant %d", variant)
	}
	outerEnd := 8 + int(binary.BigEndian.Uint32(blob[4:8]))
	if outerEnd > len(blob) {
		return result, fmt.Errorf("SUPF outer payload exceeds file")
	}
	count := int(binary.BigEndian.Uint32(blob[8:12]))
	if count == 0 || count > 32 {
		return result, fmt.Errorf("SUPF architecture count is invalid")
	}
	cursor := 12
	for i := 0; i < count; i++ {
		if cursor+4 > outerEnd {
			return result, fmt.Errorf("SUPF architecture length is truncated")
		}
		length := int(binary.BigEndian.Uint32(blob[cursor : cursor+4]))
		start, end := cursor+4, cursor+4+length
		if start+8 > end || end > outerEnd {
			return result, fmt.Errorf("SUPF architecture has invalid geometry")
		}
		arch := supfArchitecture{cpuType: binary.BigEndian.Uint32(blob[start : start+4]), cpuSubtype: binary.BigEndian.Uint32(blob[start+4 : start+8])}
		payload := start + 8
		if variant == 3 {
			payload += 20
		}
		if payload+4 > end {
			return result, fmt.Errorf("SUPF page count is truncated")
		}
		pages := int(binary.BigEndian.Uint32(blob[payload : payload+4]))
		keys := payload + 4
		if keys+pages*32 != end {
			return result, fmt.Errorf("SUPF page-key table has inconsistent length")
		}
		arch.records = make([][32]byte, pages)
		for page := 0; page < pages; page++ {
			copy(arch.records[page][:], blob[keys+page*32:keys+(page+1)*32])
		}
		result.architectures = append(result.architectures, arch)
		cursor = end
	}
	if cursor != outerEnd {
		return result, fmt.Errorf("SUPF records do not fill outer payload")
	}
	return result, nil
}

func (s supf) recordsFor(cpuType, cpuSubtype uint32) ([][32]byte, error) {
	for _, arch := range s.architectures {
		if arch.cpuType == cpuType && arch.cpuSubtype == cpuSubtype {
			return arch.records, nil
		}
	}
	return nil, fmt.Errorf("SUPF has no matching architecture %#x/%#x", cpuType, cpuSubtype)
}
