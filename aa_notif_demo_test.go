package main

import ("testing"
	"unsafe")

func TestUnpackNotif(t *testing.T) {
	// test with short data
	buffer := make([]byte, 1)
	Notif, err := UnpackNotif(buffer, cap(buffer))
	if Notif != nil || err == nil {
		t.Errorf("Expected UnpackNotif() to return an error")
	}
	t.Log(err)

	// long enough but all zeros - so will fail version test
	buffer = make([]byte, 1024)
	Notif, err = UnpackNotif(buffer, cap(buffer))
	if Notif != nil || err == nil {
		t.Errorf("Expected UnpackNotif() to return an error")
	}
	t.Log(err)

	// progressively set various parts until we get success
	var op *AppArmorNotifOp = (*AppArmorNotifOp)(unsafe.Pointer(&buffer))
	op.base.base.version = APPARMOR_NOTIFY_VERSION
	Notif, err = UnpackNotif(buffer, cap(buffer))
	if Notif != nil || err == nil {
		t.Errorf("Expected UnpackNotif() to return an error")
	}
	t.Log(err)

	t.Log(op.base.base.len)
	var length *uint16 = (*uint16)(unsafe.Pointer(&buffer[unsafe.Offsetof(op.base.base.len) + unsafe.Sizeof(op.base.base.len)]))
	*length = uint16(unsafe.Sizeof(*op))
	t.Log(op.base.base.len)
	Notif, err = UnpackNotif(buffer, int(unsafe.Sizeof(*op)))
	if Notif != nil || err == nil {
		t.Errorf("Expected UnpackNotif() to return an error")
	}
	t.Log(err)

	// set a label
	start := unsafe.Sizeof(op)
	name := "foo"
	for i := 0; i < len(name); i++ {
		buffer[int(start) + i] = name[i]
	}
	buffer[unsafe.Offsetof(op.label)] = byte(start)
	t.Log("label", op.label)
	// segfaults when trying to set as a 32-bit number
	// op.label = uint32(start)
	Notif, err = UnpackNotif(buffer, int(unsafe.Sizeof(*op)))
	if Notif != nil || err == nil {
		t.Errorf("Expected UnpackNotif() to return an error")
	}
	t.Log(err)

	op.op = AA_CLASS_FILE
	Notif, err = UnpackNotif(buffer, cap(buffer))
	if Notif != nil || err == nil {
		t.Errorf("Expected UnpackNotif() to return an error")
	}
	t.Log(err)
}
