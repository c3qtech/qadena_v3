// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: qadena/dsvs/v_share_signatory.proto

package types

import (
	fmt "fmt"
	_ "github.com/cosmos/cosmos-proto"
	_ "github.com/cosmos/gogoproto/gogoproto"
	proto "github.com/cosmos/gogoproto/proto"
	github_com_cosmos_gogoproto_types "github.com/cosmos/gogoproto/types"
	_ "google.golang.org/protobuf/types/known/timestamppb"
	io "io"
	math "math"
	math_bits "math/bits"
	time "time"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf
var _ = time.Kitchen

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type VShareSignatory struct {
	EncSignatoryVShare  []byte          `protobuf:"bytes,1,opt,name=encSignatoryVShare,proto3" json:"encSignatoryVShare,omitempty"`
	SignatoryVShareBind *VShareBindData `protobuf:"bytes,2,opt,name=signatoryVShareBind,proto3" json:"signatoryVShareBind,omitempty"`
	Time                time.Time       `protobuf:"bytes,3,opt,name=time,proto3,stdtime" json:"time"`
	WalletID            string          `protobuf:"bytes,4,opt,name=WalletID,proto3" json:"WalletID,omitempty"`
}

func (m *VShareSignatory) Reset()         { *m = VShareSignatory{} }
func (m *VShareSignatory) String() string { return proto.CompactTextString(m) }
func (*VShareSignatory) ProtoMessage()    {}
func (*VShareSignatory) Descriptor() ([]byte, []int) {
	return fileDescriptor_2e91796266df0849, []int{0}
}
func (m *VShareSignatory) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *VShareSignatory) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_VShareSignatory.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *VShareSignatory) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VShareSignatory.Merge(m, src)
}
func (m *VShareSignatory) XXX_Size() int {
	return m.Size()
}
func (m *VShareSignatory) XXX_DiscardUnknown() {
	xxx_messageInfo_VShareSignatory.DiscardUnknown(m)
}

var xxx_messageInfo_VShareSignatory proto.InternalMessageInfo

func (m *VShareSignatory) GetEncSignatoryVShare() []byte {
	if m != nil {
		return m.EncSignatoryVShare
	}
	return nil
}

func (m *VShareSignatory) GetSignatoryVShareBind() *VShareBindData {
	if m != nil {
		return m.SignatoryVShareBind
	}
	return nil
}

func (m *VShareSignatory) GetTime() time.Time {
	if m != nil {
		return m.Time
	}
	return time.Time{}
}

func (m *VShareSignatory) GetWalletID() string {
	if m != nil {
		return m.WalletID
	}
	return ""
}

func init() {
	proto.RegisterType((*VShareSignatory)(nil), "qadena.dsvs.VShareSignatory")
}

func init() {
	proto.RegisterFile("qadena/dsvs/v_share_signatory.proto", fileDescriptor_2e91796266df0849)
}

var fileDescriptor_2e91796266df0849 = []byte{
	// 300 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x52, 0x2e, 0x4c, 0x4c, 0x49,
	0xcd, 0x4b, 0xd4, 0x4f, 0x29, 0x2e, 0x2b, 0xd6, 0x2f, 0x8b, 0x2f, 0xce, 0x48, 0x2c, 0x4a, 0x8d,
	0x2f, 0xce, 0x4c, 0xcf, 0x4b, 0x2c, 0xc9, 0x2f, 0xaa, 0xd4, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17,
	0xe2, 0x86, 0x28, 0xd2, 0x03, 0x29, 0x92, 0x12, 0x49, 0xcf, 0x4f, 0xcf, 0x07, 0x8b, 0xeb, 0x83,
	0x58, 0x10, 0x25, 0x52, 0x92, 0xc9, 0xf9, 0xc5, 0xb9, 0xf9, 0xc5, 0xf1, 0x10, 0x09, 0x08, 0x07,
	0x2a, 0x25, 0x9f, 0x9e, 0x9f, 0x9f, 0x9e, 0x93, 0xaa, 0x0f, 0xe6, 0x25, 0x95, 0xa6, 0xe9, 0x97,
	0x64, 0xe6, 0xa6, 0x16, 0x97, 0x24, 0xe6, 0x16, 0x40, 0x15, 0x60, 0x75, 0x43, 0x52, 0x66, 0x5e,
	0x4a, 0x7c, 0x4a, 0x62, 0x49, 0x22, 0x44, 0x91, 0xd2, 0x33, 0x46, 0x2e, 0xfe, 0xb0, 0x60, 0x90,
	0x54, 0x30, 0xcc, 0x75, 0x42, 0x7a, 0x5c, 0x42, 0xa9, 0x79, 0xc9, 0x70, 0x3e, 0x44, 0x5a, 0x82,
	0x51, 0x81, 0x51, 0x83, 0x27, 0x08, 0x8b, 0x8c, 0x90, 0x2f, 0x97, 0x70, 0x31, 0xaa, 0x90, 0x53,
	0x66, 0x5e, 0x8a, 0x04, 0x93, 0x02, 0xa3, 0x06, 0xb7, 0x91, 0xb4, 0x1e, 0x92, 0x2f, 0xf5, 0x10,
	0xd2, 0x2e, 0x89, 0x25, 0x89, 0x41, 0xd8, 0xf4, 0x09, 0x59, 0x70, 0xb1, 0x80, 0xbc, 0x22, 0xc1,
	0x0c, 0xd6, 0x2f, 0xa5, 0x07, 0xf1, 0xa7, 0x1e, 0xcc, 0x9f, 0x7a, 0x21, 0x30, 0x7f, 0x3a, 0x71,
	0x9c, 0xb8, 0x27, 0xcf, 0x30, 0xe1, 0xbe, 0x3c, 0x63, 0x10, 0x58, 0x87, 0x90, 0x14, 0x17, 0x47,
	0x78, 0x62, 0x4e, 0x4e, 0x6a, 0x89, 0xa7, 0x8b, 0x04, 0x8b, 0x02, 0xa3, 0x06, 0x67, 0x10, 0x9c,
	0xef, 0xa4, 0x7b, 0xe2, 0x91, 0x1c, 0xe3, 0x85, 0x47, 0x72, 0x8c, 0x0f, 0x1e, 0xc9, 0x31, 0x4e,
	0x78, 0x2c, 0xc7, 0x70, 0xe1, 0xb1, 0x1c, 0xc3, 0x8d, 0xc7, 0x72, 0x0c, 0x51, 0xc2, 0xd0, 0x70,
	0xaa, 0x80, 0x84, 0x54, 0x49, 0x65, 0x41, 0x6a, 0x71, 0x12, 0x1b, 0xd8, 0x3a, 0x63, 0x40, 0x00,
	0x00, 0x00, 0xff, 0xff, 0x0f, 0x57, 0x5a, 0xf5, 0xc9, 0x01, 0x00, 0x00,
}

func (m *VShareSignatory) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *VShareSignatory) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *VShareSignatory) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.WalletID) > 0 {
		i -= len(m.WalletID)
		copy(dAtA[i:], m.WalletID)
		i = encodeVarintVShareSignatory(dAtA, i, uint64(len(m.WalletID)))
		i--
		dAtA[i] = 0x22
	}
	n1, err1 := github_com_cosmos_gogoproto_types.StdTimeMarshalTo(m.Time, dAtA[i-github_com_cosmos_gogoproto_types.SizeOfStdTime(m.Time):])
	if err1 != nil {
		return 0, err1
	}
	i -= n1
	i = encodeVarintVShareSignatory(dAtA, i, uint64(n1))
	i--
	dAtA[i] = 0x1a
	if m.SignatoryVShareBind != nil {
		{
			size, err := m.SignatoryVShareBind.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintVShareSignatory(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if len(m.EncSignatoryVShare) > 0 {
		i -= len(m.EncSignatoryVShare)
		copy(dAtA[i:], m.EncSignatoryVShare)
		i = encodeVarintVShareSignatory(dAtA, i, uint64(len(m.EncSignatoryVShare)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintVShareSignatory(dAtA []byte, offset int, v uint64) int {
	offset -= sovVShareSignatory(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *VShareSignatory) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.EncSignatoryVShare)
	if l > 0 {
		n += 1 + l + sovVShareSignatory(uint64(l))
	}
	if m.SignatoryVShareBind != nil {
		l = m.SignatoryVShareBind.Size()
		n += 1 + l + sovVShareSignatory(uint64(l))
	}
	l = github_com_cosmos_gogoproto_types.SizeOfStdTime(m.Time)
	n += 1 + l + sovVShareSignatory(uint64(l))
	l = len(m.WalletID)
	if l > 0 {
		n += 1 + l + sovVShareSignatory(uint64(l))
	}
	return n
}

func sovVShareSignatory(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozVShareSignatory(x uint64) (n int) {
	return sovVShareSignatory(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *VShareSignatory) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowVShareSignatory
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
			return fmt.Errorf("proto: VShareSignatory: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: VShareSignatory: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field EncSignatoryVShare", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowVShareSignatory
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
				return ErrInvalidLengthVShareSignatory
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthVShareSignatory
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.EncSignatoryVShare = append(m.EncSignatoryVShare[:0], dAtA[iNdEx:postIndex]...)
			if m.EncSignatoryVShare == nil {
				m.EncSignatoryVShare = []byte{}
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SignatoryVShareBind", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowVShareSignatory
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthVShareSignatory
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthVShareSignatory
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.SignatoryVShareBind == nil {
				m.SignatoryVShareBind = &VShareBindData{}
			}
			if err := m.SignatoryVShareBind.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Time", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowVShareSignatory
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthVShareSignatory
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthVShareSignatory
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := github_com_cosmos_gogoproto_types.StdTimeUnmarshal(&m.Time, dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field WalletID", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowVShareSignatory
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
				return ErrInvalidLengthVShareSignatory
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthVShareSignatory
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.WalletID = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipVShareSignatory(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthVShareSignatory
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
func skipVShareSignatory(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowVShareSignatory
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
					return 0, ErrIntOverflowVShareSignatory
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
					return 0, ErrIntOverflowVShareSignatory
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
				return 0, ErrInvalidLengthVShareSignatory
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupVShareSignatory
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthVShareSignatory
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthVShareSignatory        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowVShareSignatory          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupVShareSignatory = fmt.Errorf("proto: unexpected end of group")
)
