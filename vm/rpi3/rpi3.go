// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build rpi3

package rpi3

/*
#cgo CFLAGS: -I${SRCDIR}/CP2112/include
#cgo LDFLAGS: -L${SRCDIR}/CP2112/lib/x86_64 -lslabhidtosmbus -lslabhiddevice
#include <stdint.h>
#include <SLABCP2112.h>
*/
import "C"

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	// "os/exec"
	"path/filepath"
	// "reflect"
	"time"
	// "unsafe"

	"github.com/google/syzkaller/pkg/config"
	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/vm/vmimpl"
)

const VID C.WORD = 0x10c4
const PID C.WORD = 0xea90
var dev C.HID_SMBUS_DEVICE		// device context

func init() {

		fmt.Println("init rpi3")

	vmimpl.Register("rpi3", ctor)
}

type Config struct {
	Host_Addr  string // ip address of the host machine
	Slave_Addr string // ip address of the Odroid board
	Console    string // console device name (e.g. "/dev/ttyUSB0")
	Reset_Pin  uint
	// Hub_Bus    int    // host USB bus number for the USB hub
	// Hub_Device int    // host USB device number for the USB hub
	// Hub_Port   int    // port on the USB hub to which Odroid is connected
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
}

type instance struct {
	cfg    *Config
	sshkey string
	closed chan bool
	debug  bool
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse odroid vm config: %v", err)
	}
	if cfg.Host_Addr == "" {
		return nil, fmt.Errorf("config param host_addr is empty")
	}
	if cfg.Slave_Addr == "" {
		return nil, fmt.Errorf("config param slave_addr is empty")
	}
	if cfg.Console == "" {
		return nil, fmt.Errorf("config param console is empty")
	}
	if cfg.Reset_Pin == 0 {
		return nil, fmt.Errorf("config param reset_pin is empty")
	}
	// if cfg.Hub_Bus == 0 {
	// 	return nil, fmt.Errorf("config param hub_bus is empty")
	// }
	// if cfg.Hub_Device == 0 {
	// 	return nil, fmt.Errorf("config param hub_device is empty")
	// }
	// if cfg.Hub_Port == 0 {
	// 	return nil, fmt.Errorf("config param hub_port is empty")
	// }
	if !osutil.IsExist(env.SshKey) {
		return nil, fmt.Errorf("ssh key '%v' does not exist", env.SshKey)
	}
	if !osutil.IsExist(cfg.Console) {
		return nil, fmt.Errorf("console file '%v' does not exist", cfg.Console)
	}
	pool := &Pool{
		cfg: cfg,
		env: env,
	}
	return pool, nil
}

func (pool *Pool) Count() int {
	return 1 // no support for multiple Odroid devices yet
}

func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	inst := &instance{
		cfg:    pool.cfg,
		sshkey: pool.env.SshKey,
		closed: make(chan bool),
		debug:  pool.env.Debug,
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()
	if err := inst.repair(); err != nil {
		return nil, err
	}

	// Create working dir if doesn't exist.
	inst.ssh("mkdir -p /data/")

	// Remove temp files from previous runs.
	inst.ssh("rm -rf /data/syzkaller-*")

	closeInst = nil
	return inst, nil
}

func (inst *instance) Forward(port int) (string, error) {
	return fmt.Sprintf(inst.cfg.Host_Addr+":%v", port), nil
}

func (inst *instance) ssh(command string) ([]byte, error) {
	if inst.debug {
		Logf(0, "executing ssh %+v", command)
	}

	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, err
	}

	args := append(inst.sshArgs("-p"), "root@"+inst.cfg.Slave_Addr, command)
	if inst.debug {
		Logf(0, "running command: ssh %#v", args)
	}
	cmd := osutil.Command("ssh", args...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		wpipe.Close()
		return nil, err
	}
	wpipe.Close()

	done := make(chan bool)
	go func() {
		select {
		case <-time.After(time.Minute):
			if inst.debug {
				Logf(0, "ssh hanged")
			}
			cmd.Process.Kill()
		case <-done:
		}
	}()
	if err := cmd.Wait(); err != nil {
		close(done)
		out, _ := ioutil.ReadAll(rpipe)
		if inst.debug {
			Logf(0, "ssh failed: %v\n%s", err, out)
		}
		return nil, fmt.Errorf("ssh %+v failed: %v\n%s", args, err, out)
	}
	close(done)
	if inst.debug {
		Logf(0, "ssh returned")
	}
	out, _ := ioutil.ReadAll(rpipe)
	return out, nil
}

func setResetSignal(gpioNumber uint, reset bool) error {
	if err := C.HidSmbus_Open(&dev, 0, VID, PID); err != C.HID_SMBUS_SUCCESS {
		return fmt.Errorf("HidSmbus_Open() -> : %v", err)
	}
	defer C.HidSmbus_Close(dev)

	var gpioMask C.BYTE = 1 << gpioNumber
	var direction C.BYTE
	var mode C.BYTE
	var special C.BYTE
	var clkDiv C.BYTE

	if err := C.HidSmbus_GetGpioConfig(dev, &direction, &mode, &special, &clkDiv); err != C.HID_SMBUS_SUCCESS {
		return fmt.Errorf("HidSmbus_GetGpioConfig() -> : %v", err)
	}
	fmt.Println("GPIO config:", direction, mode, special, clkDiv)

	// config Open-Drain Output
	direction |= gpioMask
	mode &= ^gpioMask

	if err := C.HidSmbus_SetGpioConfig(dev, direction, mode, special, clkDiv); err != C.HID_SMBUS_SUCCESS {
		return fmt.Errorf("HidSmbus_SetGpioConfig() -> : %v", err)
	}
	fmt.Println("GPIO config:", direction, mode, special, clkDiv)

	var latchValue C.BYTE
	if err := C.HidSmbus_ReadLatch(dev, &latchValue); err != C.HID_SMBUS_SUCCESS {
		return fmt.Errorf("HidSmbus_ReadLatch() -> : %v", err)
	}
	fmt.Println("GPIO latchValue:", latchValue)

	var writeValue C.BYTE
	if reset {
		writeValue = 0
	} else {
		writeValue = gpioMask
	}
	if err := C.HidSmbus_WriteLatch(dev, writeValue, gpioMask); err != C.HID_SMBUS_SUCCESS {
		return fmt.Errorf("HidSmbus_WriteLatch() -> : %v", err)
	}
	fmt.Println("GPIO writeValue:", writeValue, gpioMask)

	return nil
}

// func switchPortPower(busNum, deviceNum, portNum int, power bool) error {
// 	var context *C.libusb_context
// 	if err := C.libusb_init(&context); err != 0 {
// 		return fmt.Errorf("failed to init libusb: %v\n", err)
// 	}
// 	defer C.libusb_exit(context)
//
// 	var rawList **C.libusb_device
// 	numDevices := int(C.libusb_get_device_list(context, &rawList))
// 	if numDevices < 0 {
// 		return fmt.Errorf("failed to init libusb: %v", numDevices)
// 	}
// 	defer C.libusb_free_device_list(rawList, 1)
//
// 	var deviceList []*C.libusb_device
// 	*(*reflect.SliceHeader)(unsafe.Pointer(&deviceList)) = reflect.SliceHeader{
// 		Data: uintptr(unsafe.Pointer(rawList)),
// 		Len:  numDevices,
// 		Cap:  numDevices,
// 	}
//
// 	var hub *C.libusb_device
// 	for i := 0; i < numDevices; i++ {
// 		var desc C.struct_libusb_device_descriptor
// 		if err := C.libusb_get_device_descriptor(deviceList[i], &desc); err != 0 {
// 			return fmt.Errorf("failed to get device descriptor: %v", err)
// 		}
// 		if desc.bDeviceClass != C.USB_CLASS_HUB {
// 			continue
// 		}
// 		if C.libusb_get_bus_number(deviceList[i]) != C.uint8_t(busNum) {
// 			continue
// 		}
// 		if C.libusb_get_device_address(deviceList[i]) != C.uint8_t(deviceNum) {
// 			continue
// 		}
// 		hub = deviceList[i]
// 		break
// 	}
//
// 	if hub == nil {
// 		return fmt.Errorf("hub not found: bus: %v, device: %v", busNum, deviceNum)
// 	}
//
// 	var handle *C.libusb_device_handle
// 	if err := C.libusb_open(hub, &handle); err != 0 {
// 		return fmt.Errorf("failed to open usb device: %v", err)
// 	}
//
// 	request := C.uint8_t(C.USB_REQ_CLEAR_FEATURE)
// 	if power {
// 		request = C.uint8_t(C.USB_REQ_SET_FEATURE)
// 	}
// 	port := C.uint16_t(portNum)
// 	timeout := C.uint(1000)
// 	if err := C.libusb_control_transfer(handle, C.USB_RT_PORT, request,
// 		C.USB_PORT_FEAT_POWER, port, nil, 0, timeout); err < 0 {
// 		return fmt.Errorf("failed to send control message: %v\n", err)
// 	}
//
// 	return nil
// }

func (inst *instance) repair() error {
	// Try to shutdown gracefully.
	Logf(1, "rpi3: trying to ssh")
	if err := inst.waitForSsh(10); err == nil {
		Logf(1, "rpi3: ssh succeeded, shutting down now")
		inst.ssh("shutdown now")
		if !vmimpl.SleepInterruptible(20 * time.Second) {
			return fmt.Errorf("shutdown in progress")
		}
	} else {
		Logf(1, "rpi3: ssh failed")
	}

	// Hard reset by turning off and back on power on a hub port.
	Logf(1, "rpi3: hard reset, turning off power")
	if err := setResetSignal(inst.cfg.Reset_Pin, true); err != nil {
		return err
	}
	if !vmimpl.SleepInterruptible(5 * time.Second) {
		return fmt.Errorf("shutdown in progress")
	}
	if err := setResetSignal(inst.cfg.Reset_Pin, false); err != nil {
		return err
	}

	// Now wait for boot.
	Logf(1, "rpi3: power back on, waiting for boot")
	if err := inst.waitForSsh(150); err != nil {
		return err
	}

	Logf(1, "rpi3: boot succeeded")
	return nil
}

func (inst *instance) waitForSsh(timeout int) error {
	var err error
	start := time.Now()
	for {
		if !vmimpl.SleepInterruptible(time.Second) {
			return fmt.Errorf("shutdown in progress")
		}
		if _, err = inst.ssh("pwd"); err == nil {
			return nil
		}
		if time.Since(start).Seconds() > float64(timeout) {
			break
		}
	}
	return fmt.Errorf("instance is dead and unrepairable: %v", err)
}

func (inst *instance) Close() {
	close(inst.closed)
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	basePath := "/data/"
	vmDst := filepath.Join(basePath, filepath.Base(hostSrc))
	args := append(inst.sshArgs("-P"), hostSrc, "root@"+inst.cfg.Slave_Addr+":"+vmDst)
	cmd := osutil.Command("scp", args...)
	if inst.debug {
		Logf(0, "running command: scp %#v", args)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stdout
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan bool)
	go func() {
		select {
		case <-time.After(3 * time.Minute):
			cmd.Process.Kill()
		case <-done:
		}
	}()
	err := cmd.Wait()
	close(done)
	if err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (<-chan []byte, <-chan error, error) {
	tty, err := vmimpl.OpenConsole(inst.cfg.Console)
	if err != nil {
		return nil, nil, err
	}

	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		tty.Close()
		return nil, nil, err
	}

	args := append(inst.sshArgs("-p"), "root@"+inst.cfg.Slave_Addr, "cd /data; "+command)
	if inst.debug {
		Logf(0, "running command: ssh %#v", args)
	}
	cmd := osutil.Command("ssh", args...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		tty.Close()
		rpipe.Close()
		wpipe.Close()
		return nil, nil, err
	}
	wpipe.Close()

	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	merger := vmimpl.NewOutputMerger(tee)
	merger.Add("console", tty)
	merger.Add("ssh", rpipe)

	errc := make(chan error, 1)
	signal := func(err error) {
		select {
		case errc <- err:
		default:
		}
	}

	go func() {
		select {
		case <-time.After(timeout):
			signal(vmimpl.TimeoutErr)
		case <-stop:
			signal(vmimpl.TimeoutErr)
		case <-inst.closed:
			if inst.debug {
				Logf(0, "instance closed")
			}
			signal(fmt.Errorf("instance closed"))
		case err := <-merger.Err:
			cmd.Process.Kill()
			tty.Close()
			merger.Wait()
			if cmdErr := cmd.Wait(); cmdErr == nil {
				// If the command exited successfully, we got EOF error from merger.
				// But in this case no error has happened and the EOF is expected.
				err = nil
			}
			signal(err)
			return
		}
		cmd.Process.Kill()
		tty.Close()
		merger.Wait()
		cmd.Wait()
	}()
	return merger.Output, errc, nil
}

func (inst *instance) sshArgs(portArg string) []string {
	args := []string{
		"-i", inst.sshkey,
		portArg, "22",
		"-F", "/dev/null",
		"-o", "ConnectionAttempts=10",
		"-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "LogLevel=error",
	}
	if inst.debug {
		args = append(args, "-v")
	}
	return args
}
