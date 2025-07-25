// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: qadena/qadena/interval_public_key_i_d.proto

package types

import (
	fmt "fmt"
	proto "github.com/cosmos/gogoproto/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type IntervalPublicKeyID struct {
	NodeID              string `protobuf:"bytes,1,opt,name=nodeID,proto3" json:"nodeID,omitempty"`
	NodeType            string `protobuf:"bytes,2,opt,name=nodeType,proto3" json:"nodeType,omitempty"`
	PubKID              string `protobuf:"bytes,3,opt,name=pubKID,proto3" json:"pubKID,omitempty"`
	ExternalIPAddress   string `protobuf:"bytes,4,opt,name=externalIPAddress,proto3" json:"externalIPAddress,omitempty"`
	ServiceProviderType string `protobuf:"bytes,5,opt,name=serviceProviderType,proto3" json:"serviceProviderType,omitempty"`
	RemoteReport        []byte `protobuf:"bytes,6,opt,name=remoteReport,proto3" json:"remoteReport,omitempty"`
}

func (m *IntervalPublicKeyID) Reset()         { *m = IntervalPublicKeyID{} }
func (m *IntervalPublicKeyID) String() string { return proto.CompactTextString(m) }
func (*IntervalPublicKeyID) ProtoMessage()    {}
func (*IntervalPublicKeyID) Descriptor() ([]byte, []int) {
	return fileDescriptor_272bf86d61bec731, []int{0}
}
func (m *IntervalPublicKeyID) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *IntervalPublicKeyID) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_IntervalPublicKeyID.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *IntervalPublicKeyID) XXX_Merge(src proto.Message) {
	xxx_messageInfo_IntervalPublicKeyID.Merge(m, src)
}
func (m *IntervalPublicKeyID) XXX_Size() int {
	return m.Size()
}
func (m *IntervalPublicKeyID) XXX_DiscardUnknown() {
	xxx_messageInfo_IntervalPublicKeyID.DiscardUnknown(m)
}

var xxx_messageInfo_IntervalPublicKeyID proto.InternalMessageInfo

func (m *IntervalPublicKeyID) GetNodeID() string {
	if m != nil {
		return m.NodeID
	}
	return ""
}

func (m *IntervalPublicKeyID) GetNodeType() string {
	if m != nil {
		return m.NodeType
	}
	return ""
}

func (m *IntervalPublicKeyID) GetPubKID() string {
	if m != nil {
		return m.PubKID
	}
	return ""
}

func (m *IntervalPublicKeyID) GetExternalIPAddress() string {
	if m != nil {
		return m.ExternalIPAddress
	}
	return ""
}

func (m *IntervalPublicKeyID) GetServiceProviderType() string {
	if m != nil {
		return m.ServiceProviderType
	}
	return ""
}

func (m *IntervalPublicKeyID) GetRemoteReport() []byte {
	if m != nil {
		return m.RemoteReport
	}
	return nil
}

func init() {
	proto.RegisterType((*IntervalPublicKeyID)(nil), "qadena.qadena.IntervalPublicKeyID")
}

func init() {
	proto.RegisterFile("qadena/qadena/interval_public_key_i_d.proto", fileDescriptor_272bf86d61bec731)
}

var fileDescriptor_272bf86d61bec731 = []byte{
	// 279 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x90, 0xcf, 0x4a, 0xc3, 0x40,
	0x18, 0xc4, 0xb3, 0xfe, 0x09, 0xba, 0xd4, 0x83, 0x5b, 0x90, 0xe0, 0x61, 0x29, 0x3d, 0x15, 0x2a,
	0x89, 0x90, 0x27, 0x50, 0xe2, 0x21, 0xf4, 0x12, 0x82, 0x27, 0x2f, 0x21, 0xc9, 0x7e, 0xd8, 0xc5,
	0x34, 0xbb, 0xdd, 0x6c, 0x42, 0xf3, 0x16, 0x3e, 0x96, 0xc7, 0x1e, 0x3d, 0x4a, 0x82, 0xef, 0x21,
	0xdd, 0x44, 0x41, 0xf4, 0x34, 0x3b, 0x3b, 0xbf, 0xe1, 0x83, 0xc1, 0xcb, 0x6d, 0xca, 0xa0, 0x4c,
	0xbd, 0x51, 0x78, 0xa9, 0x41, 0x35, 0x69, 0x91, 0xc8, 0x3a, 0x2b, 0x78, 0x9e, 0xbc, 0x40, 0x9b,
	0xf0, 0x84, 0xb9, 0x52, 0x09, 0x2d, 0xc8, 0xc5, 0x40, 0xb9, 0x83, 0xcc, 0x3f, 0x11, 0x9e, 0x86,
	0x63, 0x21, 0x32, 0xfc, 0x0a, 0xda, 0x30, 0x20, 0x57, 0xd8, 0x2e, 0x05, 0x83, 0x30, 0x70, 0xd0,
	0x0c, 0x2d, 0xce, 0xe3, 0xd1, 0x91, 0x6b, 0x7c, 0x76, 0x78, 0x3d, 0xb6, 0x12, 0x9c, 0x23, 0x93,
	0xfc, 0xf8, 0x43, 0x47, 0xd6, 0xd9, 0x2a, 0x0c, 0x9c, 0xe3, 0xa1, 0x33, 0x38, 0x72, 0x83, 0x2f,
	0x61, 0xa7, 0x41, 0x95, 0x69, 0x11, 0x46, 0x77, 0x8c, 0x29, 0xa8, 0x2a, 0xe7, 0xc4, 0x20, 0x7f,
	0x03, 0x72, 0x8b, 0xa7, 0x15, 0xa8, 0x86, 0xe7, 0x10, 0x29, 0xd1, 0x70, 0x06, 0xca, 0x1c, 0x3b,
	0x35, 0xfc, 0x7f, 0x11, 0x99, 0xe3, 0x89, 0x82, 0x8d, 0xd0, 0x10, 0x83, 0x14, 0x4a, 0x3b, 0xf6,
	0x0c, 0x2d, 0x26, 0xf1, 0xaf, 0xbf, 0xfb, 0x87, 0xb7, 0x8e, 0xa2, 0x7d, 0x47, 0xd1, 0x47, 0x47,
	0xd1, 0x6b, 0x4f, 0xad, 0x7d, 0x4f, 0xad, 0xf7, 0x9e, 0x5a, 0x4f, 0xcb, 0x67, 0xae, 0xd7, 0x75,
	0xe6, 0xe6, 0x62, 0xe3, 0xe5, 0xfe, 0x56, 0x43, 0xbe, 0x1e, 0x97, 0x4c, 0x1a, 0xdf, 0xdb, 0x7d,
	0xaf, 0xaa, 0x5b, 0x09, 0x55, 0x66, 0x9b, 0x11, 0xfd, 0xaf, 0x00, 0x00, 0x00, 0xff, 0xff, 0x54,
	0x9b, 0x5f, 0xf5, 0x73, 0x01, 0x00, 0x00,
}

func (m *IntervalPublicKeyID) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *IntervalPublicKeyID) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *IntervalPublicKeyID) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.RemoteReport) > 0 {
		i -= len(m.RemoteReport)
		copy(dAtA[i:], m.RemoteReport)
		i = encodeVarintIntervalPublicKeyID(dAtA, i, uint64(len(m.RemoteReport)))
		i--
		dAtA[i] = 0x32
	}
	if len(m.ServiceProviderType) > 0 {
		i -= len(m.ServiceProviderType)
		copy(dAtA[i:], m.ServiceProviderType)
		i = encodeVarintIntervalPublicKeyID(dAtA, i, uint64(len(m.ServiceProviderType)))
		i--
		dAtA[i] = 0x2a
	}
	if len(m.ExternalIPAddress) > 0 {
		i -= len(m.ExternalIPAddress)
		copy(dAtA[i:], m.ExternalIPAddress)
		i = encodeVarintIntervalPublicKeyID(dAtA, i, uint64(len(m.ExternalIPAddress)))
		i--
		dAtA[i] = 0x22
	}
	if len(m.PubKID) > 0 {
		i -= len(m.PubKID)
		copy(dAtA[i:], m.PubKID)
		i = encodeVarintIntervalPublicKeyID(dAtA, i, uint64(len(m.PubKID)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.NodeType) > 0 {
		i -= len(m.NodeType)
		copy(dAtA[i:], m.NodeType)
		i = encodeVarintIntervalPublicKeyID(dAtA, i, uint64(len(m.NodeType)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.NodeID) > 0 {
		i -= len(m.NodeID)
		copy(dAtA[i:], m.NodeID)
		i = encodeVarintIntervalPublicKeyID(dAtA, i, uint64(len(m.NodeID)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintIntervalPublicKeyID(dAtA []byte, offset int, v uint64) int {
	offset -= sovIntervalPublicKeyID(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *IntervalPublicKeyID) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.NodeID)
	if l > 0 {
		n += 1 + l + sovIntervalPublicKeyID(uint64(l))
	}
	l = len(m.NodeType)
	if l > 0 {
		n += 1 + l + sovIntervalPublicKeyID(uint64(l))
	}
	l = len(m.PubKID)
	if l > 0 {
		n += 1 + l + sovIntervalPublicKeyID(uint64(l))
	}
	l = len(m.ExternalIPAddress)
	if l > 0 {
		n += 1 + l + sovIntervalPublicKeyID(uint64(l))
	}
	l = len(m.ServiceProviderType)
	if l > 0 {
		n += 1 + l + sovIntervalPublicKeyID(uint64(l))
	}
	l = len(m.RemoteReport)
	if l > 0 {
		n += 1 + l + sovIntervalPublicKeyID(uint64(l))
	}
	return n
}

func sovIntervalPublicKeyID(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozIntervalPublicKeyID(x uint64) (n int) {
	return sovIntervalPublicKeyID(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *IntervalPublicKeyID) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowIntervalPublicKeyID
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
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
			return fmt.Errorf("proto: IntervalPublicKeyID: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: IntervalPublicKeyID: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field NodeID", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIntervalPublicKeyID
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
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
				return ErrInvalidLengthIntervalPublicKeyID
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthIntervalPublicKeyID
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.NodeID = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field NodeType", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIntervalPublicKeyID
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
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
				return ErrInvalidLengthIntervalPublicKeyID
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthIntervalPublicKeyID
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.NodeType = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PubKID", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIntervalPublicKeyID
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
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
				return ErrInvalidLengthIntervalPublicKeyID
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthIntervalPublicKeyID
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.PubKID = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ExternalIPAddress", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIntervalPublicKeyID
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
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
				return ErrInvalidLengthIntervalPublicKeyID
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthIntervalPublicKeyID
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ExternalIPAddress = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ServiceProviderType", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIntervalPublicKeyID
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
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
				return ErrInvalidLengthIntervalPublicKeyID
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthIntervalPublicKeyID
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ServiceProviderType = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field RemoteReport", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIntervalPublicKeyID
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthIntervalPublicKeyID
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthIntervalPublicKeyID
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.RemoteReport = append(m.RemoteReport[:0], dAtA[iNdEx:postIndex]...)
			if m.RemoteReport == nil {
				m.RemoteReport = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipIntervalPublicKeyID(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthIntervalPublicKeyID
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipIntervalPublicKeyID(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowIntervalPublicKeyID
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowIntervalPublicKeyID
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowIntervalPublicKeyID
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthIntervalPublicKeyID
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupIntervalPublicKeyID
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthIntervalPublicKeyID
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthIntervalPublicKeyID        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowIntervalPublicKeyID          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupIntervalPublicKeyID = fmt.Errorf("proto: unexpected end of group")
)
