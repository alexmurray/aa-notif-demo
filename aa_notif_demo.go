package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// corresponds to pid_t
type PID uint32

// corresponds to uid_t
type UID uint32

type Modeset uint32

const (
	APPARMOR_MODESET_COMPLAIN Modeset = 1
	APPARMOR_MODESET_ENFORCE          = 2
	APPARMOR_MODESET_HINT             = 4
	APPARMOR_MODESET_STATUS           = 8
	APPARMOR_MODESET_SYNC             = 16
	APPARMOR_MODESET_KILL             = 32
	APPARMOR_MODESET_ERROR            = 64
)

const (
	APPARMOR_NOTIF_RESP               = iota // starts at 0
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
const APPARMOR_NOTIF_SET_FILTER = 0x4008F800
const APPARMOR_NOTIF_GET_FILTER = 0x8008F801
const APPARMOR_NOTIF_IS_ID_VALID = 0x8008F803
const APPARMOR_NOTIF_RECV = 0xC008F804
const APPARMOR_NOTIF_SEND = 0xC008F805

const APPARMOR_NOTIFY_VERSION = 2

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
	file() NotifFile
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

func (n NotifFile) file() NotifFile {
	return n
}

func PolicyNotificationOpen() (listener int, err error) {
	var base string = ""
	f, err := os.OpenFile("/proc/mounts", os.O_RDONLY, os.ModePerm)
	if err != nil {
		return -1, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		parts := strings.Split(line, " ")
		if parts[0] == "securityfs" {
			_, err := os.Stat(parts[1] + "/apparmor")
			if (err == nil) {
				base = parts[1] + "/apparmor"
				break			}
		}
	}
	if (base == "") {
		return -1, errors.New("Unable to find securityfs in /proc/mounts - is it mounted?")
	}
	path := base + "/.notify"
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

func main() {
	fd, err := PolicyNotificationOpen()
	if err != nil {
		log.Fatalf("Failed to open AppArmor notification interface: %s", err)
	}

	err = PolicyNotificationRegister(fd, APPARMOR_MODESET_SYNC)
	if err != nil {
		log.Fatalf("Failed to register for sync notifications: %s", err)
	}

	epfd, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		log.Fatalf("Failed to create epoll fd: %s", err)
	}
	var event syscall.EpollEvent
	event.Events = syscall.EPOLLIN | syscall.EPOLLOUT
	err = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, fd, &event)
	if err != nil {
		log.Fatalf("Failed to add epoll fd: %s", err)
	}

	for {
		// poll until ready to read so we can do the ioctl only when data
		// is available
		var events []syscall.EpollEvent
		var timeout int = -1
		n, err := syscall.EpollWait(epfd, events, timeout)
		if err != nil {
			log.Printf("Error doing EpollWait(): %s\n", err)
			// TODO - handle EAGAIN etc? but exit for now
			break
		}

		// read input from the user to authorise or not
		reader := bufio.NewReader(os.Stdin)
		for i := 0; i < n; i++ {
			event := events[i]
			if event.Events & syscall.EPOLLIN != 0 {
				// read via ioctl
				raw := AppArmorNotifCommon{}
				raw.Len = 4096
				raw.Version = APPARMOR_NOTIFY_VERSION

				// encode as a 4096 byte array
				buffer := new(bytes.Buffer)
				err := binary.Write(buffer, binary.LittleEndian, raw)
				if err != nil {
					log.Printf("Error encoding header for APPARMOR_NOTIF_RECV ioctl(): %s\n", err)
				}
				// set the rest to zero and expand length
				// of array in the process
				for i := 0; i < int(raw.Len) - 4; i++ {
					var zero byte = 0
					err := binary.Write(buffer, binary.LittleEndian, zero)
					if err != nil {
						log.Printf("Error encoding remaining data for APPARMOR_NOTIF_RECV ioctl(): %s\n", err)
					}
				}
				data := buffer.Bytes()
				ret, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(event.Fd), APPARMOR_NOTIF_RECV, uintptr(unsafe.Pointer(&data)))
				if errno != 0 {
					log.Printf("Error in ioctl(APPARMOR_NOTIF_RECV): %d\n", syscall.Errno(errno))
					continue
				}
				if int(ret) <= 0 {
					log.Printf("Unexpected return value from ioctl: %d\n", ret)
					continue
				}
				req, err := UnpackNotif(data, int(ret))
				if (err != nil) {
					log.Printf("Failed to unpack AppArmorNotif of length %d\n", int(ret))
					// TODO - we should still send a response
					continue
				}
				log.Println("Received req", req)
				fmt.Printf("Allow profile: %s to access: '%s' allow 0x%x deny 0x%x error: %d (y/n) >",
					req.label(), req.file().name, req.allow(), req.deny(), req.error())
				line, _ := reader.ReadString('\n')
				// strip newline etc
				response := strings.Replace(line, "\n", "", -1)

				resp := AppArmorNotifResp{}
				resp.Base.Common.Version = APPARMOR_NOTIFY_VERSION
				resp.Base.Common.Len = uint16(unsafe.Sizeof(resp))
				resp.Base.NType = APPARMOR_NOTIF_RESP
				resp.Base.ID = req.id()

				if strings.Compare(response, "y") == 0 {
					fmt.Println("  allowing access")
					resp.Error = 0
					resp.Allow = req.allow() | req.deny()
					resp.Deny = 0
				} else {
					fmt.Println("  denying access")
					resp.Error = req.error()
					resp.Allow = req.allow()
					resp.Deny = req.deny()
				}

				buffer = new(bytes.Buffer)
				err = binary.Write(buffer, binary.LittleEndian, resp)
				if err != nil {
					log.Println("Error encoding response to APPARMOR_NOTIF_RESP - unable to reply", err)
					continue
				}
				data = buffer.Bytes()
				ret, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(event.Fd), APPARMOR_NOTIF_SEND, uintptr(unsafe.Pointer(&data)))
				if errno != 0 {
					log.Println("Error in ioctl(APPARMOR_NOTIF_SEND)", syscall.Errno(errno))
					continue
				}
				if ret != unsafe.Sizeof(resp) {
					log.Println("Unexpected return value from ioctl", ret)
					continue
				}
			} else {
				log.Printf("Unhandled epoll event 0x%x\n", event.Events)
			}
		}
	}
}
