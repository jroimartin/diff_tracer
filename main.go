package main

import (
	"bufio"
	"debug/elf"
	"flag"
	"fmt"
	"math"
	"os"
	"runtime"
)

const (
	TRACE1 = 0x1
	TRACE2 = 0x2
)

var (
	cmd       = flag.Bool("cmd", false, "Command to execute")
	diff      = flag.Bool("diff", false, "Diff traces")
	startAddr = uint64(math.MaxUint64)
	endAddr   = uint64(0)
)

func usage() {
	fmt.Printf("usage: diff_tracer -cmd cmd args > traceX\n")
	fmt.Printf("       diff_tracer -diff trace1 trace2 > diff.idc\n\n")
	flag.PrintDefaults()
}

func main() {
	var err error

	runtime.LockOSThread()

	flag.Usage = usage
	flag.Parse()

	switch {
	case *cmd && flag.NArg() > 0:
		err = cmdMode(flag.Arg(0), flag.Args()[1:])
	case *diff && flag.NArg() == 2:
		err = diffMode(flag.Arg(0), flag.Arg(1))
	default:
		usage()
		os.Exit(1)
	}
	if err != nil {
		panic(err)
	}
}

func cmdMode(cmd string, args []string) error {
	f, err := elf.Open(cmd)
	if err != nil {
		return err
	}
	defer f.Close()

	// Set mem limits
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if p.Vaddr < startAddr {
			startAddr = p.Vaddr
		}
		if addr := p.Vaddr + p.Memsz; addr > endAddr {
			endAddr = addr
		}
	}

	pt, err := ForkExec(cmd, args)
	if err != nil {
		return err
	}
	if err := pt.Wait(printPC); err != nil {
		return err
	}
	return nil
}

func diffMode(trace1, trace2 string) error {
	t1, err := readTrace(trace1)
	if err != nil {
		return err
	}
	t2, err := readTrace(trace2)
	if err != nil {
		return err
	}
	diff := make(map[uint64]uint)
	for _, addr := range t1 {
		diff[addr] |= TRACE1
	}
	for _, addr := range t2 {
		diff[addr] |= TRACE2
	}
	outputIDC(diff)
	return nil
}

func printPC(pt *Ptrace) error {
	regs, err := pt.Regs()
	if err != nil {
		return err
	}
	if pc := regs.PC(); pc >= startAddr && pc <= endAddr {
		fmt.Printf("0x%08x\n", regs.PC())
	}
	return nil
}

func readTrace(trace string) ([]uint64, error) {
	f, err := os.Open(trace)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	t := make([]uint64, 0, 1024)
	s := bufio.NewScanner(f)
	for s.Scan() {
		n, err := ParseUint64(s.Text())
		if err != nil {
			return nil, err
		}
		t = append(t, n)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return t, nil
}

func outputIDC(diff map[uint64]uint) {
	fmt.Println("#include <idc.idc>")
	fmt.Println("static main() {")
	for k, v := range diff {
		switch v {
		case TRACE1:
			fmt.Printf("SetColor(0x%08x, CIC_ITEM, 0x33CC33);\n", k)
		case TRACE2:
			fmt.Printf("SetColor(0x%08x, CIC_ITEM, 0x0000CC);\n", k)
		case TRACE1 | TRACE2:
			fmt.Printf("SetColor(0x%08x, CIC_ITEM, 0xCCCCCC);\n", k)
		}
	}
	fmt.Println("}")
}
