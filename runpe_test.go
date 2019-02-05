package runpe

import "testing"

func TestRelocEntry(t *testing.T) {
	tt := []struct {
		val    uint16
		typ    uint16
		offset uint32
	}{
		{val: 0x0000, typ: 0, offset: 0},
		{val: 0xF000, typ: 0x0F, offset: 0},
		{val: 0xE0EE, typ: 0x0E, offset: 0xEE},
		{val: 0x0DDD, typ: 0, offset: 0xDDD},
	}

	for _, tc := range tt {
		e := baseRelocEntry(tc.val)
		if uint16(e.Type()) != tc.typ {
			t.Errorf("Expected type to be %x got %x", tc.typ, e.Type())
		}
		if e.Offset() != tc.offset {
			t.Errorf("Expected offset to be %x got %x", tc.offset, e.Offset())
		}
	}
}
