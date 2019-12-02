package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPolicyNotificationOpen(t *testing.T) {
	fd, err := PolicyNotificationOpen()
	if fd < 0 {
		if err == nil {
			t.Errorf("Expected an error but none given for fd %d", fd)
		} else {
			t.Log("Expected and got error:", err)
		}
	} else {
		if err != nil {
			t.Error("Expected no error but got one:", err)
		}
	}
}

func TestPolicyNotificationRegister(t *testing.T) {
	var expected bool
	fd, err := PolicyNotificationOpen()
	if err != nil {
		expected = true
	}
	// if fd is invalid or already have err then don't expect this to work
	err = PolicyNotificationRegister(fd, APPARMOR_MODESET_USER)
	if expected {
		if err == nil {
			t.Error("Expected error but success!")
		} else {
			t.Log("Expected and got error:", err)
		}
	} else {
		if err != nil {
			t.Error("Expected success but failed:", err)
		}
	}
}

func TestStrlen(t *testing.T) {
	buffer := []byte{'A', 'B', 0}
	expected := 2
	length := Strlen(buffer)
	if length != expected {
		t.Errorf("Expected Strlen() to return %d, got %d", expected, length)
	}
	buffer = []byte{'A', 'B', 'C'}
	expected = 3
	length = Strlen(buffer)
	if length != expected {
		t.Errorf("Expected Strlen() to return %d, got %d", expected, length)
	}
	buffer = []byte{0}
	expected = 0
	length = Strlen(buffer)
	if length != expected {
		t.Errorf("Expected Strlen() to return %d, got %d", expected, length)
	}
}

func Encode(t *testing.T, file *AppArmorNotifFile, label string, name string, order binary.ByteOrder) (notif Notif, err error) {
	buffer := new(bytes.Buffer)
	// write label after file itself
	file.Op.Base.Common.Len = uint16(int(binary.Size(*file)) + len(label) + len(name) + 2)
	file.Op.Label = uint32(binary.Size(*file))
	// write name after label with nul terminator
	file.Name = uint32(int(binary.Size(*file)) + len(label) + 1)
	err = binary.Write(buffer, order, *file)

	err = binary.Write(buffer, order, []byte(label))
	if err != nil {
		t.Error("Failed to encode for testing", err)
	}
	// add trailing NUL
	nul := string(0)
	err = binary.Write(buffer, order, []byte(nul))
	if err != nil {
		t.Error("Failed to encode for testing", err)
	}
	err = binary.Write(buffer, order, []byte(name))
	if err != nil {
		t.Error("Failed to encode for testing", err)
	}
	// add trailing NUL
	err = binary.Write(buffer, order, []byte(nul))
	if err != nil {
		t.Error("Failed to encode for testing", err)
	}
	bytes := buffer.Bytes()
	return UnpackNotif(bytes, buffer.Len(), order)
}

func EncodeAndExpectNoError(t *testing.T, file *AppArmorNotifFile, label string, name string, order binary.ByteOrder) (notif Notif) {
	notif, err := Encode(t, file, label, name, order)
	if notif == nil {
		t.Error("Expected UnpackNotif() to pass and return a Notif ", err)
		// fake one so other code doesn't bomb out
		notif = NotifFile{}
	}
	t.Log("Expected pass", notif)
	return notif
}

func EncodeAndExpectError(t *testing.T, file *AppArmorNotifFile, label string, name string, order binary.ByteOrder) {
	notif, err := Encode(t, file, label, name, order)
	if notif != nil || err == nil {
		t.Error("Expected UnpackNotif() to return an error ", notif)
	}
	t.Log("Expected error", err)
}

func TestUnpackNotif(t *testing.T) {
	order := binary.LittleEndian
	// test with empty data
	file := AppArmorNotifFile{}
	label := ""
	name := ""
	EncodeAndExpectError(t, &file, label, name, order)

	// progressively set various parts until we get success
	// version - has no class
	file.Op.Base.Common.Version = APPARMOR_NOTIFY_VERSION
	EncodeAndExpectError(t, &file, label, name, order)

	// Class
	file.Op.Class = AA_CLASS_FILE
	notif := EncodeAndExpectNoError(t, &file, label, name, order)
	if notif.class() != AA_CLASS_FILE {
		t.Error("Failed to decode correctly")
	}
	if notif.label() != label {
		t.Errorf("Failed to decode label: %s != %s", notif.label(), label)
	}
	if notif.file().name != name {
		t.Errorf("Failed to decode name: %s != %s", notif.file().name, name)
	}

	// label
	label = "barishfoo"
	// try big-endian
	notif = EncodeAndExpectNoError(t, &file, label, name, binary.BigEndian)
	if notif.label() != label {
		t.Errorf("Failed to decode label: %s != %s", notif.label(), label)
	}
	if notif.file().name != name {
		t.Errorf("Failed to decode name: %s != %s", notif.file().name, name)
	}
	// name
	name = "fooishbar"
	notif = EncodeAndExpectNoError(t, &file, label, name, order)
	if notif.label() != label {
		t.Errorf("Failed to decode label: %s != %s", notif.label(), label)
	}
	if notif.file().name != name {
		t.Errorf("Failed to decode name: %s != %s", notif.file().name, name)
	}

	// test from actual bytes - these are little endian
	data := []byte{0x66, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0xf3, 0xff, 0xff, 0xff, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x62, 0x69, 0x6e,
		0x2f, 0x6d, 0x61, 0x6e, 0x2f, 0x2f, 0x6e, 0x75, 0x6c, 0x6c, 0x2d, 0x2f, 0x75, 0x73, 0x72,
		0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x6c, 0x65, 0x73, 0x73, 0x00, 0x2f, 0x65, 0x74, 0x63, 0x2f,
		0x6c, 0x64, 0x2e, 0x73, 0x6f, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x00}
	notif, err := UnpackNotif(data, len(data), binary.LittleEndian)
	if err != nil {
		t.Errorf("Failed to decode notif: %s", err)
	} else {
		// check notif is valid
		if notif.label() != "/usr/bin/man//null-/usr/bin/less" ||
			notif.id() != 2 ||
			notif.pid() != 0 ||
			notif.allow() != 4 ||
			notif.deny() != 4 ||
			notif.error() != -13 ||
			notif.class() != AA_CLASS_FILE ||
			notif.file() == nil ||
			notif.file().name != "/etc/ld.so.cache" {
			t.Errorf("Failed to decode correctly: label: '%s', id: %d, pid: %d, allow: %d, deny: %d, error: %d, class: %d, file.name: '%s'",
				notif.label(),
				notif.id(),
				notif.pid(),
				notif.allow(),
				notif.deny(),
				notif.error(),
				notif.class(),
				notif.file().name)
		}
	}
}
