package main

import ("bytes"
	"testing"
	"encoding/binary"
)

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

func Encode(t *testing.T, file *AppArmorNotifFile, length int) (notif Notif, err error) {
	// TODO - will only work on LittleEndian platforms
	buffer := new(bytes.Buffer)
	// can't write out whole file as contains a string - so write in
	// parts and encode the Name manually
	err = binary.Write(buffer, binary.LittleEndian, file.Op)
	if err != nil {
		t.Error("Failed to encode for testing", err)
	}
	err = binary.Write(buffer, binary.LittleEndian, file.SUID)
	if err != nil {
		t.Error("Failed to encode for testing", err)
	}
	err = binary.Write(buffer, binary.LittleEndian, file.OUID)
	if err != nil {
		t.Error("Failed to encode for testing", err)
	}
	var Name uint32 = uint32(len(file.Name))
	err = binary.Write(buffer, binary.LittleEndian, Name)
	if err != nil {
		t.Error("Failed to encode for testing", err)
	}
	// encode Name as a byte array with a trailing 0
	if Name > 0 {
		file.Name += string(0)
		err = binary.Write(buffer, binary.LittleEndian, []byte(file.Name))
		if err != nil {
			t.Error("Failed to encode for testing", err)
		}
	}
	if length == -1 {
		length = buffer.Cap()
	}
	file.Op.Base.Common.Len = uint16(length)
	return UnpackNotif(buffer.Bytes(), length)
}
func EncodeAndExpectNoError(t *testing.T, file *AppArmorNotifFile, len int) {
	notif, err := Encode(t, file, len)
	if notif == nil {
		t.Error("Expected UnpackNotif() to pass and return a Notif ", err)
	}
	t.Log("Expected pass", notif)
}

func EncodeAndExpectError(t *testing.T, file *AppArmorNotifFile, len int) {
	notif, err := Encode(t, file, len)
	if notif != nil || err == nil {
		t.Error("Expected UnpackNotif() to return an error ", notif)
	}
	t.Log("Expected error", err)
}

func TestUnpackNotif(t *testing.T) {
	// test with short data
	file := AppArmorNotifFile{}
	EncodeAndExpectError(t, &file, 10)

	// progressively set various parts until we get success
	// length (-1 means use full encoded length)
	EncodeAndExpectError(t, &file, -1)

	// version
	file.Op.Base.Common.Version = APPARMOR_NOTIFY_VERSION
	EncodeAndExpectError(t, &file, -1)

	// op
	file.Op.Op = AA_CLASS_FILE
	EncodeAndExpectNoError(t, &file, -1)

	file.Name = "foo"
	EncodeAndExpectNoError(t, &file, -1)

	// file.file = AA_CLASS_FILE
	// Notif, err = UnpackNotif(buffer.Bytes(), cap(buffer))
	// if Notif != nil || err == nil {
	// 	t.Errorf("Expected UnpackNotif() to return an error")
	// }
	// t.Log(err)
}
