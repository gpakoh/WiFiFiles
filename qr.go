package main

import "errors"

// qrVersion5L builds a fixed QR Code Version 5, error-correction level L,
// byte mode, mask 0. Version 5-L carries up to 106 bytes, which is ample for
// WiFiFiles' short local mobile-upload URL.
func qrVersion5L(text string) ([]string, error) {
	const (
		version       = 5
		size          = version*4 + 17
		dataCodewords = 108
		eccCodewords  = 26
	)
	data := []byte(text)
	if len(data) > 106 {
		return nil, errors.New("qR URL is too long")
	}

	bits := make([]bool, 0, dataCodewords*8)
	appendBits := func(value, count int) {
		for i := count - 1; i >= 0; i-- {
			bits = append(bits, ((value>>i)&1) != 0)
		}
	}
	appendBits(0x4, 4) // Byte mode.
	appendBits(len(data), 8)
	for _, b := range data {
		appendBits(int(b), 8)
	}
	remaining := dataCodewords*8 - len(bits)
	if remaining > 4 {
		remaining = 4
	}
	appendBits(0, remaining)
	for len(bits)%8 != 0 {
		bits = append(bits, false)
	}
	codewords := make([]byte, 0, dataCodewords+eccCodewords)
	for i := 0; i < len(bits); i += 8 {
		var b byte
		for j := 0; j < 8; j++ {
			if bits[i+j] {
				b |= 1 << (7 - j)
			}
		}
		codewords = append(codewords, b)
	}
	for pad := 0; len(codewords) < dataCodewords; pad++ {
		if pad%2 == 0 {
			codewords = append(codewords, 0xEC)
		} else {
			codewords = append(codewords, 0x11)
		}
	}
	divisor := reedSolomonDivisor(eccCodewords)
	codewords = append(codewords, reedSolomonRemainder(codewords, divisor)...)

	modules := make([][]bool, size)
	isFunction := make([][]bool, size)
	for y := 0; y < size; y++ {
		modules[y] = make([]bool, size)
		isFunction[y] = make([]bool, size)
	}
	setFunction := func(x, y int, dark bool) {
		modules[y][x] = dark
		isFunction[y][x] = true
	}
	abs := func(v int) int {
		if v < 0 {
			return -v
		}
		return v
	}
	drawFinder := func(x, y int) {
		for dy := -1; dy <= 7; dy++ {
			for dx := -1; dx <= 7; dx++ {
				xx, yy := x+dx, y+dy
				if xx < 0 || yy < 0 || xx >= size || yy >= size {
					continue
				}
				d := abs(dx - 3)
				if v := abs(dy - 3); v > d {
					d = v
				}
				setFunction(xx, yy, d != 2 && d != 4)
			}
		}
	}
	drawFinder(0, 0)
	drawFinder(size-7, 0)
	drawFinder(0, size-7)
	for i := 8; i < size-8; i++ {
		setFunction(6, i, i%2 == 0)
		setFunction(i, 6, i%2 == 0)
	}
	// Version 5 alignment pattern centers are 6 and 30. The three patterns
	// overlapping finder patterns are omitted, leaving only (30,30).
	for dy := -2; dy <= 2; dy++ {
		for dx := -2; dx <= 2; dx++ {
			d := abs(dx)
			if v := abs(dy); v > d {
				d = v
			}
			setFunction(30+dx, 30+dy, d != 1)
		}
	}

	// Reserve and draw format information for error-correction L, mask 0.
	formatData := 1 << 3 // L has format bits 01; mask pattern is 000.
	rem := formatData
	for i := 0; i < 10; i++ {
		rem = (rem << 1) ^ ((rem >> 9) * 0x537)
	}
	formatBits := ((formatData << 10) | rem) ^ 0x5412
	bit := func(i int) bool { return ((formatBits >> i) & 1) != 0 }
	for i := 0; i <= 5; i++ {
		setFunction(8, i, bit(i))
	}
	setFunction(8, 7, bit(6))
	setFunction(8, 8, bit(7))
	setFunction(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		setFunction(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		setFunction(size-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		setFunction(8, size-15+i, bit(i))
	}
	setFunction(8, size-8, true) // Always-dark module.

	bitIndex := 0
	for right := size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < size; vert++ {
			upward := ((right + 1) & 2) == 0
			y := vert
			if upward {
				y = size - 1 - vert
			}
			for j := 0; j < 2; j++ {
				x := right - j
				if isFunction[y][x] {
					continue
				}
				dark := false
				if bitIndex < len(codewords)*8 {
					dark = ((codewords[bitIndex>>3] >> (7 - (bitIndex & 7))) & 1) != 0
					bitIndex++
				}
				if (x+y)%2 == 0 { // Mask pattern 0.
					dark = !dark
				}
				modules[y][x] = dark
			}
		}
	}
	if bitIndex != len(codewords)*8 {
		return nil, errors.New("qR data placement failed")
	}
	rows := make([]string, size)
	for y := 0; y < size; y++ {
		row := make([]byte, size)
		for x := 0; x < size; x++ {
			if modules[y][x] {
				row[x] = '1'
			} else {
				row[x] = '0'
			}
		}
		rows[y] = string(row)
	}
	return rows, nil
}

func reedSolomonMultiply(x, y byte) byte {
	var z byte
	for i := 7; i >= 0; i-- {
		z = (z << 1) ^ ((z >> 7) * 0x1D)
		if ((y >> i) & 1) != 0 {
			z ^= x
		}
	}
	return z
}

func reedSolomonDivisor(degree int) []byte {
	result := make([]byte, degree)
	result[degree-1] = 1
	root := byte(1)
	for i := 0; i < degree; i++ {
		for j := 0; j < degree; j++ {
			result[j] = reedSolomonMultiply(result[j], root)
			if j+1 < degree {
				result[j] ^= result[j+1]
			}
		}
		root = reedSolomonMultiply(root, 0x02)
	}
	return result
}

func reedSolomonRemainder(data, divisor []byte) []byte {
	result := make([]byte, len(divisor))
	for _, b := range data {
		factor := b ^ result[0]
		copy(result, result[1:])
		result[len(result)-1] = 0
		for i, coef := range divisor {
			result[i] ^= reedSolomonMultiply(coef, factor)
		}
	}
	return result
}
