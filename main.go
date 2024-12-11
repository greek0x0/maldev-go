package main

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/f1zm0/acheron"
	"golang.org/x/sys/windows"
)

const nullptr = uintptr(0)

func rockyQuerySystemInformation(systemInformationClass uint32, bufferSize uint32) ([]byte, error) {
	ach, err := acheron.New()
	if err != nil {
		return nil, err
	}

	_, _ = ach.Syscall(
		ach.HashString("NtQuerySystemInformation"),
		uintptr(systemInformationClass),
		0,
		uintptr(bufferSize),
		uintptr(unsafe.Pointer(&bufferSize)),
	)

	buf := make([]byte, bufferSize)

	if _, err := ach.Syscall(
		ach.HashString("NtQuerySystemInformation"),
		uintptr(systemInformationClass),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(bufferSize),
		nullptr,
	); err != nil {
		return nil, err
	}

	return buf, nil
}

func queryProcessByName(processName string) error {
	bufferSize := uint32(0)

	buf, err := rockyQuerySystemInformation(0x5, bufferSize)
	if err != nil {
		return err
	}

	offset := 0
	for {
		p := (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buf[offset]))
		processNameStr := p.ImageName.String()
		if processNameStr != "" {
			if strings.EqualFold(processNameStr, processName) {
				fmt.Printf("found process: %s, pid: %d\n", processNameStr, p.UniqueProcessID)
			}
		}
		if p.NextEntryOffset == 0 {
			break
		}
		offset += int(p.NextEntryOffset)
	}

	return nil
}

func main() {
	processName := "explorer.exe"
	if err := queryProcessByName(processName); err != nil {
		fmt.Println("error:", err)
	} else {
		fmt.Println("success")
	}

	bufferSize := uint32(0)
	buf, err := rockyQuerySystemInformation(0x5, bufferSize)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	offset := 0
	for {
		p := (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buf[offset]))
		processNameStr := p.ImageName.String()
		if processNameStr != "" {
			fmt.Printf("pid: %d, name: %s\n", p.UniqueProcessID, processNameStr)
		}
		if p.NextEntryOffset == 0 {
			break
		}
		offset += int(p.NextEntryOffset)
	}
}

