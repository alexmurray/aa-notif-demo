package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// corresponds to pid_t
type Pid uint32

// corresponds to uid_t
type Uid uint32

type Modeset int

const (
	APPARMOR_MODESET_COMPLAIN Modeset = 1
	APPARMOR_MODESET_ENFORCE          = 2
	APPARMOR_MODESET_HINT             = 4
	APPARMOR_MODESET_STATUS           = 8
	APPARMOR_MODESET_SYNC             = 16
	APPARMOR_MODESET_KILL             = 32
	APPARMOR_MODESET_ERROR            = 64
)

type NotifType int

const (
	APPARMOR_NOTIF_RESP     NotifType = iota
	APPARMOR_NOTIF_CANCEL             = iota
	APPARMOR_NOTIF_INTERUPT           = iota
	APPARMOR_NOTIF_ALIVE              = iota
	APPARMOR_NOTIF_OP                 = iota
)

// ioctls
const APPARMOR_IOC_MAGIC = 0xF8

/* Flags for apparmor notification fd ioctl. */
const APPARMOR_NOTIF_SET_FILTER = 0x4010F800
const APPARMOR_NOTIF_GET_FILTER = 0x8010F801
const APPARMOR_NOTIF_IS_ID_VALID = 0x8008F803
const APPARMOR_NOTIF_RECV = 0xC014F804
const APPARMOR_NOTIF_SEND = 0xC010F805

const APPARMOR_NOTIFY_VERSION = 1

/* base notification struct embedded as head of notifications to userspace */
type AppArmorNotifCommon struct {
	len     uint16 /* actual len data */
	version uint16 /* interface version */
}

type AppArmorNotifFilter struct {
	base    AppArmorNotifCommon
	modeset Modeset /* which notification mode */
	ns      uint32  /* offset into data */
	filter  uint32  /* offset into data */

	data []byte
}

type AppArmorNotif struct {
	base      AppArmorNotifCommon
	ntype     uint16 /* notify type */
	signalled uint8
	reserved  uint8
	id        uint64 /* unique id, not gloablly unique*/
	error     int32  /* error if unchanged */
}

type AppArmorNotifUpdate struct {
	base AppArmorNotif
	ttl  uint16 /* max keep alives left */
}

/* userspace response to notification that expects a response */
type AppArmorNotifResp struct {
	base  AppArmorNotif
	error int32 /* error if unchanged */
	allow uint32
	deny  uint32
}

type AppArmorNotifOp struct {
	base  AppArmorNotif
	allow uint32
	deny  uint32
	pid_t Pid    /* pid of task causing notification */
	label uint32 /* offset into data */
	class uint16
	op    uint16
}

type AppArmorNotifFile struct {
	base AppArmorNotifOp
	suid Uid
	ouid Uid
	name uint32 /* offset into data */

	data []byte
}

type NotifBase struct {
	id    uint64
	error int32
	allow uint32
	deny  uint32
	pid   Pid
	class uint16
	op    uint16
	label []byte
}

type NotifFile struct {
	base NotifBase
	suid Uid
	ouid Uid
	name []byte
}

type Notif interface {
}

type NotifBuffer struct {
	buffer [4096]byte
}

func PolicyNotificationOpen() (listener int, err error) {
	// TODO - look this up by parsing /proc/mounts to find where
	// securityfs is mounted - and then looking within that for
	// apparmor/.notify - so we can handle non-standard mount locations
	path := "/sys/kernel/security/apparmor/.notify"
	return syscall.Open(path, syscall.O_RDWR|syscall.O_NONBLOCK, 0644)
}

func PolicyNotificationRegister(listener int, modeset Modeset) error {
	var req AppArmorNotifFilter
	req.base.len = uint16(unsafe.Sizeof(req))
	req.base.version = APPARMOR_NOTIFY_VERSION
	req.modeset = modeset
	// no way to specify this currently, so assume is not present for
	// now
	req.ns = 0
	// no way to specify this currently, so assume is not present for
	// now
	req.filter = 0

	ret, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(listener), APPARMOR_NOTIF_SET_FILTER, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return syscall.Errno(errno)
	}
	// expect this to echo the size of the data written back on
	// success, this is a way of testing we are getting the structure
	// args right
	if uint16(ret) != req.base.len {
		panic(fmt.Sprintf("Got unexpected return value %d from ioctl() [expected %d]", uint16(ret), req.base.len))
	}
	return nil
}

func main() {
	listener, err := PolicyNotificationOpen()
	if err != nil {
		panic(fmt.Sprintf("Failed to open AppArmor notification interface: %s", err))
	}

	err = PolicyNotificationRegister(listener, APPARMOR_MODESET_SYNC)
	if err != nil {
		panic(fmt.Sprintf("Failed to register for sync notifications: %s", err))
	}
}
