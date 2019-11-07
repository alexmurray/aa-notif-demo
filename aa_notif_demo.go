package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"syscall"
	"unsafe"
)

// corresponds to pid_t
type PID uint32

// corresponds to uid_t
type UID uint32

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
	Len     uint16 /* actual len data */
	Version uint16 /* interface version */
}

type AppArmorNotifFilter struct {
	Base    AppArmorNotifCommon
	Modeset Modeset /* which notification mode */
	NS      uint32  /* offset into data */
	Filter  uint32  /* offset into data */

	// data []byte
}

type AppArmorNotif struct {
	Common    AppArmorNotifCommon
	NType     uint16 /* notify type */
	Signalled uint8
	Reserved  uint8
	ID        uint64 /* unique id, not gloablly unique*/
	Error     int32  /* error if unchanged */
}

type AppArmorNotifUpdate struct {
	Base AppArmorNotif
	TTL  uint16 /* max keep alives left */
}

/* userspace response to notification that expects a response */
type AppArmorNotifResp struct {
	Base  AppArmorNotif
	Error int32 /* error if unchanged */
	Allow uint32
	Deny  uint32
}

type AppArmorNotifOp struct {
	Base  AppArmorNotif
	Allow uint32
	Deny  uint32
	PID   PID    /* pid of task causing notification */
	Label uint32 /* offset into data */
	Class uint16
	Op    uint16
}

type AppArmorNotifFile struct {
	Op AppArmorNotifOp
	SUID UID
	OUID UID
	Name string
}

type NotifBase struct {
	id    uint64
	error int32
	allow uint32
	deny  uint32
	pid   PID
	class uint16
	op    uint16
	label string
}

type Notif interface {
	id() uint64
	error() int32
	allow() uint32
	deny() uint32
	pid() PID
	class() uint16
	op() uint16
	label() string
}

type NotifFile struct {
	base NotifBase
	suid UID
	ouid UID
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

func (n NotifFile) pid() PID {
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
	req.Base.Len = uint16(unsafe.Sizeof(req))
	req.Base.Version = APPARMOR_NOTIFY_VERSION
	req.Modeset = modeset
	// no way to specify these currently, so assume is not present for
	// now
	req.NS = 0
	req.Filter = 0

	ret, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), APPARMOR_NOTIF_SET_FILTER, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return syscall.Errno(errno)
	}
	// expect this to echo the size of the data written back on
	// success, this is a way of testing we are getting the structure
	// args right
	if uint16(ret) != req.Base.Len {
		return errors.New(fmt.Sprintf("Got unexpected return value %d from ioctl() [expected %d]", uint16(ret), req.Base.Len))
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
	op := new(AppArmorNotifOp)
	buf := bytes.NewReader(buffer)

	// progressively read and check parameters
	err = binary.Read(buf, binary.LittleEndian, op)
	if err != nil {
		return nil, err
	}
	if op.Base.Common.Version != APPARMOR_NOTIFY_VERSION {
		return nil, errors.New(fmt.Sprintf("Notification data is invalid - version != APPARMOR_NOTIFY_VERSION (%d != %d)", op.Base.Common.Version, APPARMOR_NOTIFY_VERSION))

	}
	if int(op.Base.Common.Len) != len {
		return nil, errors.New(fmt.Sprintf("Notification data is invalid - invalid length (%d != %d)", op.Base.Common.Len, len))
	}

	// check label is valid
	if int(op.Label) > len {
		return nil, errors.New(fmt.Sprintf("Notification data is invalid - label offset is out of bounds (%d >= %d)", op.Label, len))

	}
	switch op.Op {
	case AA_CLASS_FILE:
		// decode remaining file parts
		file := new(AppArmorNotifFile)
		err = binary.Read(buf, binary.LittleEndian, &file.SUID)
		if err != nil {
			return nil, err
		}
		err = binary.Read(buf, binary.LittleEndian, &file.OUID)
		if err != nil {
			return nil, err
		}
		var Name uint32
		err = binary.Read(buf, binary.LittleEndian, Name)
		if err != nil {
			return nil, err
		}
		if int(Name) > len {
			return nil, errors.New(fmt.Sprintf("Notification data is invalid - AA_CLASS_FILE name offset is out of bounds (%d > %d)", Name, len))
		}
		file.Name = string(buffer[Name:Strlen(buffer[Name:])])
		out := new(NotifFile)
		out.base.id = file.Op.Base.ID
		out.base.error = file.Op.Base.Error
		out.base.allow = file.Op.Allow
		out.base.deny = file.Op.Deny
		out.base.pid = file.Op.PID
		out.base.class = file.Op.Class
		out.base.op = file.Op.Op
		out.suid = file.SUID
		out.ouid = file.OUID
		// file.name is start of offset into buffer where the name
		// starts - we then also need the end so we can slice it as
		// a string
		out.name = file.Name
		req = out
	default:
		return nil, errors.New(fmt.Sprintf("Unknown op %d", op.Op))
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
			raw.Common.Len = uint16(cap(buffer))
			raw.Common.Version = APPARMOR_NOTIFY_VERSION
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
