// Code generated by protoc-gen-go-pulsar. DO NOT EDIT.
package dsvs

import (
	fmt "fmt"
	_ "github.com/cosmos/cosmos-proto"
	runtime "github.com/cosmos/cosmos-proto/runtime"
	_ "github.com/cosmos/gogoproto/gogoproto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoiface "google.golang.org/protobuf/runtime/protoiface"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	io "io"
	reflect "reflect"
	sync "sync"
)

var (
	md_VShareSignatory                     protoreflect.MessageDescriptor
	fd_VShareSignatory_encSignatoryVShare  protoreflect.FieldDescriptor
	fd_VShareSignatory_signatoryVShareBind protoreflect.FieldDescriptor
	fd_VShareSignatory_time                protoreflect.FieldDescriptor
	fd_VShareSignatory_WalletID            protoreflect.FieldDescriptor
)

func init() {
	file_qadena_dsvs_v_share_signatory_proto_init()
	md_VShareSignatory = File_qadena_dsvs_v_share_signatory_proto.Messages().ByName("VShareSignatory")
	fd_VShareSignatory_encSignatoryVShare = md_VShareSignatory.Fields().ByName("encSignatoryVShare")
	fd_VShareSignatory_signatoryVShareBind = md_VShareSignatory.Fields().ByName("signatoryVShareBind")
	fd_VShareSignatory_time = md_VShareSignatory.Fields().ByName("time")
	fd_VShareSignatory_WalletID = md_VShareSignatory.Fields().ByName("WalletID")
}

var _ protoreflect.Message = (*fastReflection_VShareSignatory)(nil)

type fastReflection_VShareSignatory VShareSignatory

func (x *VShareSignatory) ProtoReflect() protoreflect.Message {
	return (*fastReflection_VShareSignatory)(x)
}

func (x *VShareSignatory) slowProtoReflect() protoreflect.Message {
	mi := &file_qadena_dsvs_v_share_signatory_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

var _fastReflection_VShareSignatory_messageType fastReflection_VShareSignatory_messageType
var _ protoreflect.MessageType = fastReflection_VShareSignatory_messageType{}

type fastReflection_VShareSignatory_messageType struct{}

func (x fastReflection_VShareSignatory_messageType) Zero() protoreflect.Message {
	return (*fastReflection_VShareSignatory)(nil)
}
func (x fastReflection_VShareSignatory_messageType) New() protoreflect.Message {
	return new(fastReflection_VShareSignatory)
}
func (x fastReflection_VShareSignatory_messageType) Descriptor() protoreflect.MessageDescriptor {
	return md_VShareSignatory
}

// Descriptor returns message descriptor, which contains only the protobuf
// type information for the message.
func (x *fastReflection_VShareSignatory) Descriptor() protoreflect.MessageDescriptor {
	return md_VShareSignatory
}

// Type returns the message type, which encapsulates both Go and protobuf
// type information. If the Go type information is not needed,
// it is recommended that the message descriptor be used instead.
func (x *fastReflection_VShareSignatory) Type() protoreflect.MessageType {
	return _fastReflection_VShareSignatory_messageType
}

// New returns a newly allocated and mutable empty message.
func (x *fastReflection_VShareSignatory) New() protoreflect.Message {
	return new(fastReflection_VShareSignatory)
}

// Interface unwraps the message reflection interface and
// returns the underlying ProtoMessage interface.
func (x *fastReflection_VShareSignatory) Interface() protoreflect.ProtoMessage {
	return (*VShareSignatory)(x)
}

// Range iterates over every populated field in an undefined order,
// calling f for each field descriptor and value encountered.
// Range returns immediately if f returns false.
// While iterating, mutating operations may only be performed
// on the current field descriptor.
func (x *fastReflection_VShareSignatory) Range(f func(protoreflect.FieldDescriptor, protoreflect.Value) bool) {
	if len(x.EncSignatoryVShare) != 0 {
		value := protoreflect.ValueOfBytes(x.EncSignatoryVShare)
		if !f(fd_VShareSignatory_encSignatoryVShare, value) {
			return
		}
	}
	if x.SignatoryVShareBind != nil {
		value := protoreflect.ValueOfMessage(x.SignatoryVShareBind.ProtoReflect())
		if !f(fd_VShareSignatory_signatoryVShareBind, value) {
			return
		}
	}
	if x.Time != nil {
		value := protoreflect.ValueOfMessage(x.Time.ProtoReflect())
		if !f(fd_VShareSignatory_time, value) {
			return
		}
	}
	if x.WalletID != "" {
		value := protoreflect.ValueOfString(x.WalletID)
		if !f(fd_VShareSignatory_WalletID, value) {
			return
		}
	}
}

// Has reports whether a field is populated.
//
// Some fields have the property of nullability where it is possible to
// distinguish between the default value of a field and whether the field
// was explicitly populated with the default value. Singular message fields,
// member fields of a oneof, and proto2 scalar fields are nullable. Such
// fields are populated only if explicitly set.
//
// In other cases (aside from the nullable cases above),
// a proto3 scalar field is populated if it contains a non-zero value, and
// a repeated field is populated if it is non-empty.
func (x *fastReflection_VShareSignatory) Has(fd protoreflect.FieldDescriptor) bool {
	switch fd.FullName() {
	case "qadena.dsvs.VShareSignatory.encSignatoryVShare":
		return len(x.EncSignatoryVShare) != 0
	case "qadena.dsvs.VShareSignatory.signatoryVShareBind":
		return x.SignatoryVShareBind != nil
	case "qadena.dsvs.VShareSignatory.time":
		return x.Time != nil
	case "qadena.dsvs.VShareSignatory.WalletID":
		return x.WalletID != ""
	default:
		if fd.IsExtension() {
			panic(fmt.Errorf("proto3 declared messages do not support extensions: qadena.dsvs.VShareSignatory"))
		}
		panic(fmt.Errorf("message qadena.dsvs.VShareSignatory does not contain field %s", fd.FullName()))
	}
}

// Clear clears the field such that a subsequent Has call reports false.
//
// Clearing an extension field clears both the extension type and value
// associated with the given field number.
//
// Clear is a mutating operation and unsafe for concurrent use.
func (x *fastReflection_VShareSignatory) Clear(fd protoreflect.FieldDescriptor) {
	switch fd.FullName() {
	case "qadena.dsvs.VShareSignatory.encSignatoryVShare":
		x.EncSignatoryVShare = nil
	case "qadena.dsvs.VShareSignatory.signatoryVShareBind":
		x.SignatoryVShareBind = nil
	case "qadena.dsvs.VShareSignatory.time":
		x.Time = nil
	case "qadena.dsvs.VShareSignatory.WalletID":
		x.WalletID = ""
	default:
		if fd.IsExtension() {
			panic(fmt.Errorf("proto3 declared messages do not support extensions: qadena.dsvs.VShareSignatory"))
		}
		panic(fmt.Errorf("message qadena.dsvs.VShareSignatory does not contain field %s", fd.FullName()))
	}
}

// Get retrieves the value for a field.
//
// For unpopulated scalars, it returns the default value, where
// the default value of a bytes scalar is guaranteed to be a copy.
// For unpopulated composite types, it returns an empty, read-only view
// of the value; to obtain a mutable reference, use Mutable.
func (x *fastReflection_VShareSignatory) Get(descriptor protoreflect.FieldDescriptor) protoreflect.Value {
	switch descriptor.FullName() {
	case "qadena.dsvs.VShareSignatory.encSignatoryVShare":
		value := x.EncSignatoryVShare
		return protoreflect.ValueOfBytes(value)
	case "qadena.dsvs.VShareSignatory.signatoryVShareBind":
		value := x.SignatoryVShareBind
		return protoreflect.ValueOfMessage(value.ProtoReflect())
	case "qadena.dsvs.VShareSignatory.time":
		value := x.Time
		return protoreflect.ValueOfMessage(value.ProtoReflect())
	case "qadena.dsvs.VShareSignatory.WalletID":
		value := x.WalletID
		return protoreflect.ValueOfString(value)
	default:
		if descriptor.IsExtension() {
			panic(fmt.Errorf("proto3 declared messages do not support extensions: qadena.dsvs.VShareSignatory"))
		}
		panic(fmt.Errorf("message qadena.dsvs.VShareSignatory does not contain field %s", descriptor.FullName()))
	}
}

// Set stores the value for a field.
//
// For a field belonging to a oneof, it implicitly clears any other field
// that may be currently set within the same oneof.
// For extension fields, it implicitly stores the provided ExtensionType.
// When setting a composite type, it is unspecified whether the stored value
// aliases the source's memory in any way. If the composite value is an
// empty, read-only value, then it panics.
//
// Set is a mutating operation and unsafe for concurrent use.
func (x *fastReflection_VShareSignatory) Set(fd protoreflect.FieldDescriptor, value protoreflect.Value) {
	switch fd.FullName() {
	case "qadena.dsvs.VShareSignatory.encSignatoryVShare":
		x.EncSignatoryVShare = value.Bytes()
	case "qadena.dsvs.VShareSignatory.signatoryVShareBind":
		x.SignatoryVShareBind = value.Message().Interface().(*VShareBindData)
	case "qadena.dsvs.VShareSignatory.time":
		x.Time = value.Message().Interface().(*timestamppb.Timestamp)
	case "qadena.dsvs.VShareSignatory.WalletID":
		x.WalletID = value.Interface().(string)
	default:
		if fd.IsExtension() {
			panic(fmt.Errorf("proto3 declared messages do not support extensions: qadena.dsvs.VShareSignatory"))
		}
		panic(fmt.Errorf("message qadena.dsvs.VShareSignatory does not contain field %s", fd.FullName()))
	}
}

// Mutable returns a mutable reference to a composite type.
//
// If the field is unpopulated, it may allocate a composite value.
// For a field belonging to a oneof, it implicitly clears any other field
// that may be currently set within the same oneof.
// For extension fields, it implicitly stores the provided ExtensionType
// if not already stored.
// It panics if the field does not contain a composite type.
//
// Mutable is a mutating operation and unsafe for concurrent use.
func (x *fastReflection_VShareSignatory) Mutable(fd protoreflect.FieldDescriptor) protoreflect.Value {
	switch fd.FullName() {
	case "qadena.dsvs.VShareSignatory.signatoryVShareBind":
		if x.SignatoryVShareBind == nil {
			x.SignatoryVShareBind = new(VShareBindData)
		}
		return protoreflect.ValueOfMessage(x.SignatoryVShareBind.ProtoReflect())
	case "qadena.dsvs.VShareSignatory.time":
		if x.Time == nil {
			x.Time = new(timestamppb.Timestamp)
		}
		return protoreflect.ValueOfMessage(x.Time.ProtoReflect())
	case "qadena.dsvs.VShareSignatory.encSignatoryVShare":
		panic(fmt.Errorf("field encSignatoryVShare of message qadena.dsvs.VShareSignatory is not mutable"))
	case "qadena.dsvs.VShareSignatory.WalletID":
		panic(fmt.Errorf("field WalletID of message qadena.dsvs.VShareSignatory is not mutable"))
	default:
		if fd.IsExtension() {
			panic(fmt.Errorf("proto3 declared messages do not support extensions: qadena.dsvs.VShareSignatory"))
		}
		panic(fmt.Errorf("message qadena.dsvs.VShareSignatory does not contain field %s", fd.FullName()))
	}
}

// NewField returns a new value that is assignable to the field
// for the given descriptor. For scalars, this returns the default value.
// For lists, maps, and messages, this returns a new, empty, mutable value.
func (x *fastReflection_VShareSignatory) NewField(fd protoreflect.FieldDescriptor) protoreflect.Value {
	switch fd.FullName() {
	case "qadena.dsvs.VShareSignatory.encSignatoryVShare":
		return protoreflect.ValueOfBytes(nil)
	case "qadena.dsvs.VShareSignatory.signatoryVShareBind":
		m := new(VShareBindData)
		return protoreflect.ValueOfMessage(m.ProtoReflect())
	case "qadena.dsvs.VShareSignatory.time":
		m := new(timestamppb.Timestamp)
		return protoreflect.ValueOfMessage(m.ProtoReflect())
	case "qadena.dsvs.VShareSignatory.WalletID":
		return protoreflect.ValueOfString("")
	default:
		if fd.IsExtension() {
			panic(fmt.Errorf("proto3 declared messages do not support extensions: qadena.dsvs.VShareSignatory"))
		}
		panic(fmt.Errorf("message qadena.dsvs.VShareSignatory does not contain field %s", fd.FullName()))
	}
}

// WhichOneof reports which field within the oneof is populated,
// returning nil if none are populated.
// It panics if the oneof descriptor does not belong to this message.
func (x *fastReflection_VShareSignatory) WhichOneof(d protoreflect.OneofDescriptor) protoreflect.FieldDescriptor {
	switch d.FullName() {
	default:
		panic(fmt.Errorf("%s is not a oneof field in qadena.dsvs.VShareSignatory", d.FullName()))
	}
	panic("unreachable")
}

// GetUnknown retrieves the entire list of unknown fields.
// The caller may only mutate the contents of the RawFields
// if the mutated bytes are stored back into the message with SetUnknown.
func (x *fastReflection_VShareSignatory) GetUnknown() protoreflect.RawFields {
	return x.unknownFields
}

// SetUnknown stores an entire list of unknown fields.
// The raw fields must be syntactically valid according to the wire format.
// An implementation may panic if this is not the case.
// Once stored, the caller must not mutate the content of the RawFields.
// An empty RawFields may be passed to clear the fields.
//
// SetUnknown is a mutating operation and unsafe for concurrent use.
func (x *fastReflection_VShareSignatory) SetUnknown(fields protoreflect.RawFields) {
	x.unknownFields = fields
}

// IsValid reports whether the message is valid.
//
// An invalid message is an empty, read-only value.
//
// An invalid message often corresponds to a nil pointer of the concrete
// message type, but the details are implementation dependent.
// Validity is not part of the protobuf data model, and may not
// be preserved in marshaling or other operations.
func (x *fastReflection_VShareSignatory) IsValid() bool {
	return x != nil
}

// ProtoMethods returns optional fastReflectionFeature-path implementations of various operations.
// This method may return nil.
//
// The returned methods type is identical to
// "google.golang.org/protobuf/runtime/protoiface".Methods.
// Consult the protoiface package documentation for details.
func (x *fastReflection_VShareSignatory) ProtoMethods() *protoiface.Methods {
	size := func(input protoiface.SizeInput) protoiface.SizeOutput {
		x := input.Message.Interface().(*VShareSignatory)
		if x == nil {
			return protoiface.SizeOutput{
				NoUnkeyedLiterals: input.NoUnkeyedLiterals,
				Size:              0,
			}
		}
		options := runtime.SizeInputToOptions(input)
		_ = options
		var n int
		var l int
		_ = l
		l = len(x.EncSignatoryVShare)
		if l > 0 {
			n += 1 + l + runtime.Sov(uint64(l))
		}
		if x.SignatoryVShareBind != nil {
			l = options.Size(x.SignatoryVShareBind)
			n += 1 + l + runtime.Sov(uint64(l))
		}
		if x.Time != nil {
			l = options.Size(x.Time)
			n += 1 + l + runtime.Sov(uint64(l))
		}
		l = len(x.WalletID)
		if l > 0 {
			n += 1 + l + runtime.Sov(uint64(l))
		}
		if x.unknownFields != nil {
			n += len(x.unknownFields)
		}
		return protoiface.SizeOutput{
			NoUnkeyedLiterals: input.NoUnkeyedLiterals,
			Size:              n,
		}
	}

	marshal := func(input protoiface.MarshalInput) (protoiface.MarshalOutput, error) {
		x := input.Message.Interface().(*VShareSignatory)
		if x == nil {
			return protoiface.MarshalOutput{
				NoUnkeyedLiterals: input.NoUnkeyedLiterals,
				Buf:               input.Buf,
			}, nil
		}
		options := runtime.MarshalInputToOptions(input)
		_ = options
		size := options.Size(x)
		dAtA := make([]byte, size)
		i := len(dAtA)
		_ = i
		var l int
		_ = l
		if x.unknownFields != nil {
			i -= len(x.unknownFields)
			copy(dAtA[i:], x.unknownFields)
		}
		if len(x.WalletID) > 0 {
			i -= len(x.WalletID)
			copy(dAtA[i:], x.WalletID)
			i = runtime.EncodeVarint(dAtA, i, uint64(len(x.WalletID)))
			i--
			dAtA[i] = 0x22
		}
		if x.Time != nil {
			encoded, err := options.Marshal(x.Time)
			if err != nil {
				return protoiface.MarshalOutput{
					NoUnkeyedLiterals: input.NoUnkeyedLiterals,
					Buf:               input.Buf,
				}, err
			}
			i -= len(encoded)
			copy(dAtA[i:], encoded)
			i = runtime.EncodeVarint(dAtA, i, uint64(len(encoded)))
			i--
			dAtA[i] = 0x1a
		}
		if x.SignatoryVShareBind != nil {
			encoded, err := options.Marshal(x.SignatoryVShareBind)
			if err != nil {
				return protoiface.MarshalOutput{
					NoUnkeyedLiterals: input.NoUnkeyedLiterals,
					Buf:               input.Buf,
				}, err
			}
			i -= len(encoded)
			copy(dAtA[i:], encoded)
			i = runtime.EncodeVarint(dAtA, i, uint64(len(encoded)))
			i--
			dAtA[i] = 0x12
		}
		if len(x.EncSignatoryVShare) > 0 {
			i -= len(x.EncSignatoryVShare)
			copy(dAtA[i:], x.EncSignatoryVShare)
			i = runtime.EncodeVarint(dAtA, i, uint64(len(x.EncSignatoryVShare)))
			i--
			dAtA[i] = 0xa
		}
		if input.Buf != nil {
			input.Buf = append(input.Buf, dAtA...)
		} else {
			input.Buf = dAtA
		}
		return protoiface.MarshalOutput{
			NoUnkeyedLiterals: input.NoUnkeyedLiterals,
			Buf:               input.Buf,
		}, nil
	}
	unmarshal := func(input protoiface.UnmarshalInput) (protoiface.UnmarshalOutput, error) {
		x := input.Message.Interface().(*VShareSignatory)
		if x == nil {
			return protoiface.UnmarshalOutput{
				NoUnkeyedLiterals: input.NoUnkeyedLiterals,
				Flags:             input.Flags,
			}, nil
		}
		options := runtime.UnmarshalInputToOptions(input)
		_ = options
		dAtA := input.Buf
		l := len(dAtA)
		iNdEx := 0
		for iNdEx < l {
			preIndex := iNdEx
			var wire uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, runtime.ErrIntOverflow
				}
				if iNdEx >= l {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				wire |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			fieldNum := int32(wire >> 3)
			wireType := int(wire & 0x7)
			if wireType == 4 {
				return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, fmt.Errorf("proto: VShareSignatory: wiretype end group for non-group")
			}
			if fieldNum <= 0 {
				return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, fmt.Errorf("proto: VShareSignatory: illegal tag %d (wire type %d)", fieldNum, wire)
			}
			switch fieldNum {
			case 1:
				if wireType != 2 {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, fmt.Errorf("proto: wrong wireType = %d for field EncSignatoryVShare", wireType)
				}
				var byteLen int
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, runtime.ErrIntOverflow
					}
					if iNdEx >= l {
						return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					byteLen |= int(b&0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				if byteLen < 0 {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, runtime.ErrInvalidLength
				}
				postIndex := iNdEx + byteLen
				if postIndex < 0 {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, runtime.ErrInvalidLength
				}
				if postIndex > l {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, io.ErrUnexpectedEOF
				}
				x.EncSignatoryVShare = append(x.EncSignatoryVShare[:0], dAtA[iNdEx:postIndex]...)
				if x.EncSignatoryVShare == nil {
					x.EncSignatoryVShare = []byte{}
				}
				iNdEx = postIndex
			case 2:
				if wireType != 2 {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, fmt.Errorf("proto: wrong wireType = %d for field SignatoryVShareBind", wireType)
				}
				var msglen int
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, runtime.ErrIntOverflow
					}
					if iNdEx >= l {
						return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					msglen |= int(b&0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				if msglen < 0 {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, runtime.ErrInvalidLength
				}
				postIndex := iNdEx + msglen
				if postIndex < 0 {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, runtime.ErrInvalidLength
				}
				if postIndex > l {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, io.ErrUnexpectedEOF
				}
				if x.SignatoryVShareBind == nil {
					x.SignatoryVShareBind = &VShareBindData{}
				}
				if err := options.Unmarshal(dAtA[iNdEx:postIndex], x.SignatoryVShareBind); err != nil {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, err
				}
				iNdEx = postIndex
			case 3:
				if wireType != 2 {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, fmt.Errorf("proto: wrong wireType = %d for field Time", wireType)
				}
				var msglen int
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, runtime.ErrIntOverflow
					}
					if iNdEx >= l {
						return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					msglen |= int(b&0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				if msglen < 0 {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, runtime.ErrInvalidLength
				}
				postIndex := iNdEx + msglen
				if postIndex < 0 {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, runtime.ErrInvalidLength
				}
				if postIndex > l {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, io.ErrUnexpectedEOF
				}
				if x.Time == nil {
					x.Time = &timestamppb.Timestamp{}
				}
				if err := options.Unmarshal(dAtA[iNdEx:postIndex], x.Time); err != nil {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, err
				}
				iNdEx = postIndex
			case 4:
				if wireType != 2 {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, fmt.Errorf("proto: wrong wireType = %d for field WalletID", wireType)
				}
				var stringLen uint64
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, runtime.ErrIntOverflow
					}
					if iNdEx >= l {
						return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					stringLen |= uint64(b&0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				intStringLen := int(stringLen)
				if intStringLen < 0 {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, runtime.ErrInvalidLength
				}
				postIndex := iNdEx + intStringLen
				if postIndex < 0 {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, runtime.ErrInvalidLength
				}
				if postIndex > l {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, io.ErrUnexpectedEOF
				}
				x.WalletID = string(dAtA[iNdEx:postIndex])
				iNdEx = postIndex
			default:
				iNdEx = preIndex
				skippy, err := runtime.Skip(dAtA[iNdEx:])
				if err != nil {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, err
				}
				if (skippy < 0) || (iNdEx+skippy) < 0 {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, runtime.ErrInvalidLength
				}
				if (iNdEx + skippy) > l {
					return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, io.ErrUnexpectedEOF
				}
				if !options.DiscardUnknown {
					x.unknownFields = append(x.unknownFields, dAtA[iNdEx:iNdEx+skippy]...)
				}
				iNdEx += skippy
			}
		}

		if iNdEx > l {
			return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, io.ErrUnexpectedEOF
		}
		return protoiface.UnmarshalOutput{NoUnkeyedLiterals: input.NoUnkeyedLiterals, Flags: input.Flags}, nil
	}
	return &protoiface.Methods{
		NoUnkeyedLiterals: struct{}{},
		Flags:             protoiface.SupportMarshalDeterministic | protoiface.SupportUnmarshalDiscardUnknown,
		Size:              size,
		Marshal:           marshal,
		Unmarshal:         unmarshal,
		Merge:             nil,
		CheckInitialized:  nil,
	}
}

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.0
// 	protoc        (unknown)
// source: qadena/dsvs/v_share_signatory.proto

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type VShareSignatory struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EncSignatoryVShare  []byte                 `protobuf:"bytes,1,opt,name=encSignatoryVShare,proto3" json:"encSignatoryVShare,omitempty"`
	SignatoryVShareBind *VShareBindData        `protobuf:"bytes,2,opt,name=signatoryVShareBind,proto3" json:"signatoryVShareBind,omitempty"`
	Time                *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=time,proto3" json:"time,omitempty"`
	WalletID            string                 `protobuf:"bytes,4,opt,name=WalletID,proto3" json:"WalletID,omitempty"`
}

func (x *VShareSignatory) Reset() {
	*x = VShareSignatory{}
	if protoimpl.UnsafeEnabled {
		mi := &file_qadena_dsvs_v_share_signatory_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VShareSignatory) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VShareSignatory) ProtoMessage() {}

// Deprecated: Use VShareSignatory.ProtoReflect.Descriptor instead.
func (*VShareSignatory) Descriptor() ([]byte, []int) {
	return file_qadena_dsvs_v_share_signatory_proto_rawDescGZIP(), []int{0}
}

func (x *VShareSignatory) GetEncSignatoryVShare() []byte {
	if x != nil {
		return x.EncSignatoryVShare
	}
	return nil
}

func (x *VShareSignatory) GetSignatoryVShareBind() *VShareBindData {
	if x != nil {
		return x.SignatoryVShareBind
	}
	return nil
}

func (x *VShareSignatory) GetTime() *timestamppb.Timestamp {
	if x != nil {
		return x.Time
	}
	return nil
}

func (x *VShareSignatory) GetWalletID() string {
	if x != nil {
		return x.WalletID
	}
	return ""
}

var File_qadena_dsvs_v_share_signatory_proto protoreflect.FileDescriptor

var file_qadena_dsvs_v_share_signatory_proto_rawDesc = []byte{
	0x0a, 0x23, 0x71, 0x61, 0x64, 0x65, 0x6e, 0x61, 0x2f, 0x64, 0x73, 0x76, 0x73, 0x2f, 0x76, 0x5f,
	0x73, 0x68, 0x61, 0x72, 0x65, 0x5f, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x6f, 0x72, 0x79, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x71, 0x61, 0x64, 0x65, 0x6e, 0x61, 0x2e, 0x64, 0x73,
	0x76, 0x73, 0x1a, 0x14, 0x67, 0x6f, 0x67, 0x6f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f,
	0x67, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73,
	0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x23, 0x71, 0x61, 0x64, 0x65, 0x6e, 0x61, 0x2f, 0x64, 0x73, 0x76,
	0x73, 0x2f, 0x76, 0x5f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x5f, 0x62, 0x69, 0x6e, 0x64, 0x5f, 0x64,
	0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xe6, 0x01, 0x0a, 0x0f, 0x56, 0x53,
	0x68, 0x61, 0x72, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x6f, 0x72, 0x79, 0x12, 0x2e, 0x0a,
	0x12, 0x65, 0x6e, 0x63, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x6f, 0x72, 0x79, 0x56, 0x53, 0x68,
	0x61, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x12, 0x65, 0x6e, 0x63, 0x53, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x6f, 0x72, 0x79, 0x56, 0x53, 0x68, 0x61, 0x72, 0x65, 0x12, 0x4d, 0x0a,
	0x13, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x6f, 0x72, 0x79, 0x56, 0x53, 0x68, 0x61, 0x72, 0x65,
	0x42, 0x69, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x71, 0x61, 0x64,
	0x65, 0x6e, 0x61, 0x2e, 0x64, 0x73, 0x76, 0x73, 0x2e, 0x56, 0x53, 0x68, 0x61, 0x72, 0x65, 0x42,
	0x69, 0x6e, 0x64, 0x44, 0x61, 0x74, 0x61, 0x52, 0x13, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x6f,
	0x72, 0x79, 0x56, 0x53, 0x68, 0x61, 0x72, 0x65, 0x42, 0x69, 0x6e, 0x64, 0x12, 0x38, 0x0a, 0x04,
	0x74, 0x69, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x08, 0xc8, 0xde, 0x1f, 0x00, 0x90, 0xdf, 0x1f, 0x01,
	0x52, 0x04, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x57, 0x61, 0x6c, 0x6c, 0x65, 0x74,
	0x49, 0x44, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x57, 0x61, 0x6c, 0x6c, 0x65, 0x74,
	0x49, 0x44, 0x42, 0x92, 0x01, 0x0a, 0x0f, 0x63, 0x6f, 0x6d, 0x2e, 0x71, 0x61, 0x64, 0x65, 0x6e,
	0x61, 0x2e, 0x64, 0x73, 0x76, 0x73, 0x42, 0x14, 0x56, 0x53, 0x68, 0x61, 0x72, 0x65, 0x53, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x6f, 0x72, 0x79, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x1c,
	0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x73, 0x64, 0x6b, 0x2e, 0x69, 0x6f, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x71, 0x61, 0x64, 0x65, 0x6e, 0x61, 0x2f, 0x64, 0x73, 0x76, 0x73, 0xa2, 0x02, 0x03, 0x51,
	0x44, 0x58, 0xaa, 0x02, 0x0b, 0x51, 0x61, 0x64, 0x65, 0x6e, 0x61, 0x2e, 0x44, 0x73, 0x76, 0x73,
	0xca, 0x02, 0x0b, 0x51, 0x61, 0x64, 0x65, 0x6e, 0x61, 0x5c, 0x44, 0x73, 0x76, 0x73, 0xe2, 0x02,
	0x17, 0x51, 0x61, 0x64, 0x65, 0x6e, 0x61, 0x5c, 0x44, 0x73, 0x76, 0x73, 0x5c, 0x47, 0x50, 0x42,
	0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x0c, 0x51, 0x61, 0x64, 0x65, 0x6e,
	0x61, 0x3a, 0x3a, 0x44, 0x73, 0x76, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_qadena_dsvs_v_share_signatory_proto_rawDescOnce sync.Once
	file_qadena_dsvs_v_share_signatory_proto_rawDescData = file_qadena_dsvs_v_share_signatory_proto_rawDesc
)

func file_qadena_dsvs_v_share_signatory_proto_rawDescGZIP() []byte {
	file_qadena_dsvs_v_share_signatory_proto_rawDescOnce.Do(func() {
		file_qadena_dsvs_v_share_signatory_proto_rawDescData = protoimpl.X.CompressGZIP(file_qadena_dsvs_v_share_signatory_proto_rawDescData)
	})
	return file_qadena_dsvs_v_share_signatory_proto_rawDescData
}

var file_qadena_dsvs_v_share_signatory_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_qadena_dsvs_v_share_signatory_proto_goTypes = []interface{}{
	(*VShareSignatory)(nil),       // 0: qadena.dsvs.VShareSignatory
	(*VShareBindData)(nil),        // 1: qadena.dsvs.VShareBindData
	(*timestamppb.Timestamp)(nil), // 2: google.protobuf.Timestamp
}
var file_qadena_dsvs_v_share_signatory_proto_depIdxs = []int32{
	1, // 0: qadena.dsvs.VShareSignatory.signatoryVShareBind:type_name -> qadena.dsvs.VShareBindData
	2, // 1: qadena.dsvs.VShareSignatory.time:type_name -> google.protobuf.Timestamp
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_qadena_dsvs_v_share_signatory_proto_init() }
func file_qadena_dsvs_v_share_signatory_proto_init() {
	if File_qadena_dsvs_v_share_signatory_proto != nil {
		return
	}
	file_qadena_dsvs_v_share_bind_data_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_qadena_dsvs_v_share_signatory_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VShareSignatory); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_qadena_dsvs_v_share_signatory_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_qadena_dsvs_v_share_signatory_proto_goTypes,
		DependencyIndexes: file_qadena_dsvs_v_share_signatory_proto_depIdxs,
		MessageInfos:      file_qadena_dsvs_v_share_signatory_proto_msgTypes,
	}.Build()
	File_qadena_dsvs_v_share_signatory_proto = out.File
	file_qadena_dsvs_v_share_signatory_proto_rawDesc = nil
	file_qadena_dsvs_v_share_signatory_proto_goTypes = nil
	file_qadena_dsvs_v_share_signatory_proto_depIdxs = nil
}
