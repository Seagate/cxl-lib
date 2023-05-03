// Copyright (c) 2023 Seagate Technology LLC and/or its Affiliates

// This file implements the bitfield handling for binary structure.
// Code largely leveraged from go lang's "encoding/binary" library,
// which enables field parsing at Byte level. This file extends the
// capacity into bit level.

package cxl

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"reflect"

	"k8s.io/klog/v2"
)

type bitfield_1b uint8
type bitfield_2b uint8
type bitfield_3b uint8
type bitfield_4b uint8
type bitfield_5b uint8
type bitfield_6b uint8
type bitfield_7b uint8
type bitfield_8b uint8
type bitfield_9b uint16
type bitfield_10b uint16
type bitfield_11b uint16
type bitfield_12b uint16
type bitfield_13b uint16
type bitfield_14b uint16
type bitfield_15b uint16
type bitfield_16b uint16
type bitfield_17b uint32
type bitfield_18b uint32
type bitfield_19b uint32
type bitfield_20b uint32
type bitfield_21b uint32
type bitfield_22b uint32
type bitfield_23b uint32
type bitfield_24b uint32
type bitfield_25b uint32
type bitfield_26b uint32
type bitfield_27b uint32
type bitfield_28b uint32
type bitfield_29b uint32
type bitfield_30b uint32
type bitfield_31b uint32
type bitfield_32b uint32
type bitfield_64b uint64

// dataSize returns the number of bytes the actual data represented by v occupies in memory.
// For compound structures, it sums the sizes of the elements. Thus, for instance, for a slice
// it returns the length of the slice times the element size and does not count the memory
// occupied by the header. If the type of v is not acceptable, dataSize returns -1.
func dataSize(v reflect.Value) int {
	klog.V(4).InfoS("bitfield.dataSize", "type", v.Type().Name(), "kind", v.Kind().String())
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		klog.V(4).InfoS("bitfield.dataSize", "len", v.Len())
		if v.Len() == 0 { // deal with empty slice
			return 0
		}
		if s := dataSize(v.Index(0)); s >= 0 {
			return s * v.Len()
		}
		return -1

	case reflect.Struct:
		sum := 0
		for i, n := 0, v.NumField(); i < n; i++ {
			s := dataSize(v.Field(i))
			if s < 0 {
				return -1
			}
			sum += s
		}
		return sum

	default:
		klog.V(2).InfoS("bitfield.dataSize", "Size", v.Type().Size())
		return int(v.Type().Size())
	}
}

// Read reads structured binary data from r into data.
// Data must be a pointer to a fixed-size value or a slice
// of fixed-size values.
// Bytes read from r are decoded using the specified byte order
// and written to successive fields of the data.
// When decoding boolean values, a zero byte is decoded as false, and
// any other non-zero byte is decoded as true.
// When reading into structs, the field data for fields with
// blank (_) field names is skipped; i.e., blank field names
// may be used for padding.
// When reading into a struct, all non-blank fields must be exported
// or Read may panic.
//
// The error is EOF only if no bytes were read.
// If an EOF happens after reading some but not all the bytes,
// Read returns ErrUnexpectedEOF.

// PCIE uses little endian
func BitFieldRead(r io.Reader, data any) error {
	order := binary.LittleEndian

	v := reflect.ValueOf(data)
	size := -1
	klog.V(4).InfoS("bitfield.BitFieldRead", "type", reflect.TypeOf(data).String(), "kind", v.Kind().String())
	switch v.Kind() {
	case reflect.Pointer:
		v = v.Elem()
		size = dataSize(v)
	case reflect.Slice:
		size = dataSize(v)
	}
	if size < 0 {
		return errors.New("bitfield.BitFieldRead: invalid type " + reflect.TypeOf(data).String())
	}
	bitLengthInfoMap := bitSizeOfArray(v)

	d := &decoder{order: order, buf: make([]byte, size)}
	ReadByBit(r, d.buf, bitLengthInfoMap)
	d.value(v)
	return nil
}

func ReadByBit(r io.Reader, buf []byte, m []int) {
	rBuf := make([]byte, 4096) // Unable to decide the length of r. Support max of 4096 bytes
	io.ReadFull(r, rBuf)

	bitOfs := 0
	i := 0
	for _, width := range m {
		endBit := bitOfs + width - 1
		startByte := bitOfs >> 3
		endByte := endBit >> 3
		bitWidthMask := uint64((1 << width) - 1)
		bitShift := bitOfs - startByte*8
		val := uint64(0)
		klog.V(4).InfoS("bitfield.ReadByBit", "bitOfs", bitOfs, "bitWidth", width, "endBit", endBit, "startByte", startByte, "endByte", endByte, "bitShift", bitShift, "bitWidthMask", hex(bitWidthMask))

		// extract related field into a uint32, and then apply the shift and mask
		structByteSize := endByte - startByte
		if structByteSize < 8 {
			for iShift := 0; iShift <= structByteSize; iShift++ {
				val |= uint64(rBuf[startByte+iShift]) << (8 * iShift)
			}
		} else {
			klog.Fatal("unsupported width!")
		}
		val = (val >> uint64(bitShift)) & bitWidthMask

		dataByteSize := (width - 1) >> 3
		if dataByteSize < 8 {
			for iShift := 0; iShift <= dataByteSize; iShift++ {
				buf[i+iShift] = byte(val >> (8 * iShift))
			}
		} else {
			klog.Fatal("unsupported width!")
		}
		i += 1 + dataByteSize
		bitOfs += width
	}
}

// sizeof returns a list of the bit offset for each field
func bitSizeOfArray(v reflect.Value) []int {

	t := v.Type()
	switch t {
	case reflect.TypeOf(bitfield_1b(0)):
		return []int{1}
	case reflect.TypeOf(bitfield_2b(0)):
		return []int{2}
	case reflect.TypeOf(bitfield_3b(0)):
		return []int{3}
	case reflect.TypeOf(bitfield_4b(0)):
		return []int{4}
	case reflect.TypeOf(bitfield_5b(0)):
		return []int{5}
	case reflect.TypeOf(bitfield_6b(0)):
		return []int{6}
	case reflect.TypeOf(bitfield_7b(0)):
		return []int{7}
	case reflect.TypeOf(bitfield_8b(0)):
		return []int{8}
	case reflect.TypeOf(bitfield_9b(0)):
		return []int{9}
	case reflect.TypeOf(bitfield_10b(0)):
		return []int{10}
	case reflect.TypeOf(bitfield_11b(0)):
		return []int{11}
	case reflect.TypeOf(bitfield_12b(0)):
		return []int{12}
	case reflect.TypeOf(bitfield_13b(0)):
		return []int{13}
	case reflect.TypeOf(bitfield_14b(0)):
		return []int{14}
	case reflect.TypeOf(bitfield_15b(0)):
		return []int{15}
	case reflect.TypeOf(bitfield_16b(0)):
		return []int{16}
	case reflect.TypeOf(bitfield_17b(0)):
		return []int{17}
	case reflect.TypeOf(bitfield_18b(0)):
		return []int{18}
	case reflect.TypeOf(bitfield_19b(0)):
		return []int{19}
	case reflect.TypeOf(bitfield_20b(0)):
		return []int{20}
	case reflect.TypeOf(bitfield_21b(0)):
		return []int{21}
	case reflect.TypeOf(bitfield_22b(0)):
		return []int{22}
	case reflect.TypeOf(bitfield_23b(0)):
		return []int{23}
	case reflect.TypeOf(bitfield_24b(0)):
		return []int{24}
	case reflect.TypeOf(bitfield_25b(0)):
		return []int{25}
	case reflect.TypeOf(bitfield_26b(0)):
		return []int{26}
	case reflect.TypeOf(bitfield_27b(0)):
		return []int{27}
	case reflect.TypeOf(bitfield_28b(0)):
		return []int{28}
	case reflect.TypeOf(bitfield_29b(0)):
		return []int{29}
	case reflect.TypeOf(bitfield_30b(0)):
		return []int{30}
	case reflect.TypeOf(bitfield_31b(0)):
		return []int{31}
	case reflect.TypeOf(bitfield_32b(0)):
		return []int{32}
	case reflect.TypeOf(bitfield_64b(0)):
		return []int{64}

	}

	switch t.Kind() {
	case reflect.Array, reflect.Slice:
		structArray := []int{}
		if v.Len() != 0 {
			s := bitSizeOfArray(v.Index(0))
			for i, n := 0, v.Len(); i < n; i++ {
				structArray = append(structArray, s[:]...)
			}
		}
		return structArray
	case reflect.Struct:
		structArray := []int{}
		for i, n := 0, t.NumField(); i < n; i++ {
			s := bitSizeOfArray(v.Field(i))
			structArray = append(structArray, s[:]...)
		}
		return structArray

	case reflect.Bool,
		reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		return []int{int(t.Size()) * 8}
	}
	klog.V(2).InfoS("bitfield.bitSizeOfArray error", "kind", t.Kind().String())

	return []int{}
}

type decoder struct {
	order  binary.ByteOrder
	buf    []byte
	offset int
}

func (d *decoder) bool() bool {
	x := d.buf[d.offset]
	d.offset++
	return x != 0
}

func (d *decoder) uint8() uint8 {
	x := d.buf[d.offset]
	d.offset++
	return x
}

func (d *decoder) uint16() uint16 {
	x := d.order.Uint16(d.buf[d.offset : d.offset+2])
	d.offset += 2
	return x
}

func (d *decoder) uint32() uint32 {
	x := d.order.Uint32(d.buf[d.offset : d.offset+4])
	d.offset += 4
	return x
}

func (d *decoder) uint64() uint64 {
	x := d.order.Uint64(d.buf[d.offset : d.offset+8])
	d.offset += 8
	return x
}

func (d *decoder) int8() int8 { return int8(d.uint8()) }

func (d *decoder) int16() int16 { return int16(d.uint16()) }

func (d *decoder) int32() int32 { return int32(d.uint32()) }

func (d *decoder) int64() int64 { return int64(d.uint64()) }

func (d *decoder) value(v reflect.Value) {
	switch v.Kind() {
	case reflect.Array:
		l := v.Len()
		for i := 0; i < l; i++ {
			d.value(v.Index(i))
		}

	case reflect.Struct:
		t := v.Type()
		l := v.NumField()
		for i := 0; i < l; i++ {
			// Note: Calling v.CanSet() below is an optimization.
			// It would be sufficient to check the field name,
			// but creating the StructField info for each field is
			// costly (run "go test -bench=ReadStruct" and compare
			// results when making changes to this code).
			if v := v.Field(i); v.CanSet() || t.Field(i).Name != "_" {
				d.value(v)
			} else {
				d.skip(v)
			}
		}

	case reflect.Slice:
		l := v.Len()
		for i := 0; i < l; i++ {
			d.value(v.Index(i))
		}

	case reflect.Bool:
		v.SetBool(d.bool())

	case reflect.Int8:
		v.SetInt(int64(d.int8()))
	case reflect.Int16:
		v.SetInt(int64(d.int16()))
	case reflect.Int32:
		v.SetInt(int64(d.int32()))
	case reflect.Int64:
		v.SetInt(d.int64())

	case reflect.Uint8:
		v.SetUint(uint64(d.uint8()))
	case reflect.Uint16:
		v.SetUint(uint64(d.uint16()))
	case reflect.Uint32:
		v.SetUint(uint64(d.uint32()))
	case reflect.Uint64:
		v.SetUint(d.uint64())

	case reflect.Float32:
		v.SetFloat(float64(math.Float32frombits(d.uint32())))
	case reflect.Float64:
		v.SetFloat(math.Float64frombits(d.uint64()))

	case reflect.Complex64:
		v.SetComplex(complex(
			float64(math.Float32frombits(d.uint32())),
			float64(math.Float32frombits(d.uint32())),
		))
	case reflect.Complex128:
		v.SetComplex(complex(
			math.Float64frombits(d.uint64()),
			math.Float64frombits(d.uint64()),
		))
	}
}

func (d *decoder) skip(v reflect.Value) {
	d.offset += dataSize(v)
}
