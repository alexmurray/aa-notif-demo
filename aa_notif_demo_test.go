package main

import ("bytes"
	"testing"
	"encoding/binary"
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
	if expected  {
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

func Encode(t *testing.T, file *AppArmorNotifFile, label string, name string) (notif Notif, err error) {
	// TODO - will only work on LittleEndian platforms
	buffer := new(bytes.Buffer)
	// write label after file itself
	file.Op.Base.Common.Len = uint16(int(binary.Size(*file)) + len(label) + len(name) + 2)
	file.Op.Label = uint32(binary.Size(*file))
	// write name after label with nul terminator
	file.Name = uint32(int(binary.Size(*file)) + len(label) + 1)
	err = binary.Write(buffer, binary.LittleEndian, *file)

	err = binary.Write(buffer, binary.LittleEndian, []byte(label))
	if err != nil {
		t.Error("Failed to encode for testing", err)
	}
	// add trailing NUL
	nul := string(0)
	err = binary.Write(buffer, binary.LittleEndian, []byte(nul))
	if err != nil {
		t.Error("Failed to encode for testing", err)
	}
	err = binary.Write(buffer, binary.LittleEndian, []byte(name))
	if err != nil {
		t.Error("Failed to encode for testing", err)
	}
	// add trailing NUL
	err = binary.Write(buffer, binary.LittleEndian, []byte(nul))
	if err != nil {
		t.Error("Failed to encode for testing", err)
	}
	bytes := buffer.Bytes()
	return UnpackNotif(bytes, buffer.Len())
}

func EncodeAndExpectNoError(t *testing.T, file *AppArmorNotifFile, label string, name string) (notif Notif) {
	notif, err := Encode(t, file, label, name)
	if notif == nil {
		t.Error("Expected UnpackNotif() to pass and return a Notif ", err)
		// fake one so other code doesn't bomb out
		notif = NotifFile{}
	}
	t.Log("Expected pass", notif)
	return notif
}

func EncodeAndExpectError(t *testing.T, file *AppArmorNotifFile, label string, name string) {
	notif, err := Encode(t, file, label, name)
	if notif != nil || err == nil {
		t.Error("Expected UnpackNotif() to return an error ", notif)
	}
	t.Log("Expected error", err)
}

func TestUnpackNotif(t *testing.T) {
	// test with empty data
	file := AppArmorNotifFile{}
	label := ""
	name := ""
	EncodeAndExpectError(t, &file, label, name)

	// progressively set various parts until we get success
	// version - has no class
	file.Op.Base.Common.Version = APPARMOR_NOTIFY_VERSION
	EncodeAndExpectError(t, &file, label, name)

	// Class
	file.Op.Class = AA_CLASS_FILE
	notif := EncodeAndExpectNoError(t, &file, label, name)
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
	notif = EncodeAndExpectNoError(t, &file, label, name)
	if notif.label() != label {
		t.Errorf("Failed to decode label: %s != %s", notif.label(), label)
	}
	if notif.file().name != name {
		t.Errorf("Failed to decode name: %s != %s", notif.file().name, name)
	}
	// name
	name = "fooishbar"
	notif = EncodeAndExpectNoError(t, &file, label, name)
	if notif.label() != label {
		t.Errorf("Failed to decode label: %s != %s", notif.label(), label)
	}
	if notif.file().name != name {
		t.Errorf("Failed to decode name: %s != %s", notif.file().name, name)
	}

	// test from actual bytes
	data := []byte{0x6b, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0xf3, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4d, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x6d, 0x61,
		0x6e, 0x00, 0x2f, 0x76, 0x61, 0x72, 0x2f, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2f, 0x6d, 0x61,
		0x6e, 0x2f, 0x63, 0x61, 0x74, 0x32, 0x2f, 0x63, 0x61, 0x74, 0x50, 0x37, 0x57, 0x6f, 0x47,
		0x74, 0x00}
	notif, err := UnpackNotif(data, len(data))
	if (err != nil) {
		t.Errorf("Failed to decode notif: %s", err)
	} else {
		// check notif is valid
		if notif.label() != "/usr/bin/man" ||
			notif.id() != 3 ||
			notif.pid() != 0 ||
			notif.allow() != 0x10 ||
			notif.deny() != 0x10 ||
			notif.error() != -13 ||
			notif.class() != AA_CLASS_FILE ||
			notif.file() == nil ||
			notif.file().name != "/var/cache/man/cat2/catP7WoGt" {
			t.Errorf("Failed to decode correctly")
		}
	}
	// file.file = AA_CLASS_FILE
	// Notif, err = UnpackNotif(buffer.Bytes(), cap(buffer))
	// if Notif != nil || err == nil {
	// 	t.Errorf("Expected UnpackNotif() to return an error")
	// }
	// t.Log(err)
}
