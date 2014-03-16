package main

import (
	"errors"
	"os"
	"syscall"
)

type Ptrace struct {
	Proc *os.Process
	Addr uint64
}

func NewPtrace() *Ptrace {
	return &Ptrace{}
}

func ForkExec(cmd string, argv []string) (*Ptrace, error) {
	var err error

	pt := NewPtrace()
	attr := &os.ProcAttr{
		Env: os.Environ(),
		Sys: &syscall.SysProcAttr{Ptrace: true},
	}
	args := []string{cmd}
	args = append(args, argv...)
	pt.Proc, err = os.StartProcess(cmd, args, attr)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

func (pt *Ptrace) Read(b []byte) (n int, err error) {
	n, err = syscall.PtracePeekText(pt.Proc.Pid, uintptr(pt.Addr), b)
	if err != nil {
		return 0, err
	}
	pt.Addr += uint64(n)
	return n, nil
}

type Handler func(*Ptrace) error

func (pt *Ptrace) Wait(h Handler) error {
	if h == nil {
		return errors.New("nil handler")
	}
	for {
		status, err := pt.Proc.Wait()
		if err != nil {
			return err
		}
		if status.Exited() {
			break
		}
		if err := h(pt); err != nil {
			return err
		}
		if err := syscall.PtraceSingleStep(pt.Proc.Pid); err != nil {
			return err
		}
	}
	return nil
}

func (pt *Ptrace) Regs() (*syscall.PtraceRegs, error) {
	regs := &syscall.PtraceRegs{}
	err := syscall.PtraceGetRegs(pt.Pid(), regs)
	return regs, err
}

func (pt *Ptrace) Seek(addr uint64) {
	pt.Addr = addr
}

func (pt *Ptrace) Pid() int {
	return pt.Proc.Pid
}
