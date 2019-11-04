package main

import (
	"errors"
	"fmt"
	"log"
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

// AppArmor object classes
type Class uint16

const (
	AA_CLASS_FILE = 2
	AA_CLASS_DBUS = 32
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
	pid   Pid    /* pid of task causing notification */
	label uint32 /* offset into data */
	class uint16
	op    uint16
}

type AppArmorNotifFile struct {
	op AppArmorNotifOp
	suid Uid
	ouid Uid
	name uint32 /* offset into data */

	data []byte
}

type AppArmorNotifBuffer struct {
	buffer [4096]byte
}

type NotifBase struct {
	id    uint64
	error int32
	allow uint32
	deny  uint32
	pid   Pid
	class uint16
	op    uint16
	label string
}

type Notif interface {
	id() uint64
	error() int32
	allow() uint32
	deny() uint32
	pid() Pid
	class() uint16
	op() uint16
	label() string
}

type NotifFile struct {
	base NotifBase
	suid Uid
	ouid Uid
	name string
}

func (n NotifFile) id() uint64 {
	return n.base.id
}

func (n NotifFile) error() int32 {
	return n.base.error
}

func (n NotifFile) allow() uint32 {
	return n.base.allow
}

func (n NotifFile) deny() uint32 {
	return n.base.deny
}

func (n NotifFile) pid() Pid {
	return n.base.pid
}

func (n NotifFile) class() uint16 {
	return n.base.class
}

func (n NotifFile) op() uint16 {
	return n.base.op
}

func (n NotifFile) label() string {
	return n.base.label
}

func PolicyNotificationOpen() (listener int, err error) {
	// TODO - look this up by parsing /proc/mounts to find where
	// securityfs is mounted - and then looking within that for
	// apparmor/.notify - so we can handle non-standard mount locations
	path := "/sys/kernel/security/apparmor/.notify"
	return syscall.Open(path, syscall.O_RDWR|syscall.O_NONBLOCK, 0644)
}

func PolicyNotificationRegister(fd int, modeset Modeset) error {
	var req AppArmorNotifFilter
	req.base.len = uint16(unsafe.Sizeof(req))
	req.base.version = APPARMOR_NOTIFY_VERSION
	req.modeset = modeset
	// no way to specify these currently, so assume is not present for
	// now
	req.ns = 0
	req.filter = 0

	ret, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), APPARMOR_NOTIF_SET_FILTER, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return syscall.Errno(errno)
	}
	// expect this to echo the size of the data written back on
	// success, this is a way of testing we are getting the structure
	// args right
	if uint16(ret) != req.base.len {
		return errors.New(fmt.Sprintf("Got unexpected return value %d from ioctl() [expected %d]", uint16(ret), req.base.len))
	}
	return nil
}

// Like C strlen()
func Strlen(buffer []byte) (size int) {
	for i, c := range buffer {
		if c == 0 {
			return i
		}
	}
	return len(buffer)
}

func UnpackNotif(buffer []byte, len int) (req Notif, err error) {
	var raw *AppArmorNotifOp
	var file NotifFile
	if len < int(unsafe.Sizeof(raw)) {
		return nil, errors.New(fmt.Sprintf("Notification data is too small to unpack (%d < %d)", len, unsafe.Sizeof(raw)))
	}
	raw = (*AppArmorNotifOp)(unsafe.Pointer(&buffer))

	// check length of label is valid
	if len < int(raw.label) {
		return nil, errors.New(fmt.Sprintf("Notification data is invalid - label offset is out of bounds (%d < %d)", len, raw.label))

	}
	switch raw.op {
	case AA_CLASS_FILE:
		var rawFile *AppArmorNotifFile
		if len < int(unsafe.Sizeof(*rawFile)) {
			return nil, errors.New(fmt.Sprintf("Notification data is too small to unpack as AA_CLASS_FILE (%d < %d)", len, unsafe.Sizeof(*rawFile)))
		}
		if len < int(rawFile.name) {
			return nil, errors.New(fmt.Sprintf("Notification data is invalid - AA_CLASS_FILE name offset is out of bounds (%d < %d)", len, rawFile.name))
		}
		rawFile = (*AppArmorNotifFile)(unsafe.Pointer(raw))
		file.base.id = rawFile.op.base.id
		file.base.error = rawFile.op.base.error
		file.base.allow = rawFile.op.allow
		file.base.deny = rawFile.op.deny
		file.base.pid = rawFile.op.pid
		file.base.class = rawFile.op.class
		file.base.op = rawFile.op.op
		file.suid = rawFile.suid
		file.ouid = rawFile.ouid
		// file.name is start of offset into buffer where the name
		// starts - we then also need the end so we can slice it as
		// a string
		file.name = string(buffer[rawFile.name:(int(rawFile.name) + Strlen(buffer[rawFile.name:]))])
		req = file
	default:
		return nil, errors.New(fmt.Sprintf("Unknown op %d", raw.op))
	}
	return req, nil
}

func ReadNotif(epfd int, notifCh chan Notif) {
	// poll until ready to read so we can do the ioctl only when data
	// is available
	var events []syscall.EpollEvent
	var timeout int = -1
	n, err := syscall.EpollWait(epfd, events, timeout)
	if err != nil {
		log.Println("Error doing EpollWait()", err)
		// TODO - handle EAGAIN etc but close for now
		close(notifCh)
	}
	for i := 0; i < n; i++ {
		event := events[i]
		if event.Events & syscall.EPOLLIN != 0 {
			// read via ioctl
			buffer := make([]byte, 4096)
			var raw *AppArmorNotif = (*AppArmorNotif)(unsafe.Pointer(&buffer))
			raw.base.len = uint16(cap(buffer))
			raw.base.version = APPARMOR_NOTIFY_VERSION
			ret, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(event.Fd), APPARMOR_NOTIF_RECV, uintptr(unsafe.Pointer(&buffer)))
			if errno != 0 {
				log.Println("Error in ioctl(APPARMOR_NOTIF_RECV)", syscall.Errno(errno))
				continue
			}
			if int(ret) <= 0 {
				log.Println("Unexpected return value from ioctl", ret)
				continue
			}
			req, err := UnpackNotif(buffer, int(ret))
			if (err != nil) {
				log.Println("Failed to unpack AppArmorNotif of length", int(ret))
				continue
			}
			log.Println("Sending req", req)
			notifCh <- req
		}
	}
}

func main() {
	fd, err := PolicyNotificationOpen()
	if err != nil {
		log.Panic(fmt.Sprintf("Failed to open AppArmor notification interface: %s", err))
	}

	err = PolicyNotificationRegister(fd, APPARMOR_MODESET_SYNC)
	if err != nil {
		log.Panic(fmt.Sprintf("Failed to register for sync notifications: %s", err))
	}

	epfd, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		log.Panic(fmt.Sprintf("Failed to create epoll fd: %s", err))
	}
	var event syscall.EpollEvent
	event.Events = syscall.EPOLLIN | syscall.EPOLLOUT
	err = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, fd, &event)
	if err != nil {
		log.Panic(fmt.Sprintf("Failed to add epoll fd: %s", err))
	}

	// read in a separate go-routine
	notifCh := make(chan Notif)
	go ReadNotif(epfd, notifCh)

	for req := range notifCh {
		log.Println("Received req", req)
	}
}
