// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v3.21.4
// source: eddsa-cmp-onsign.proto

package onsign

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Represents a P2P message sent to all parties during Round 1 of the EDDSA TSS signing protocol.
type SignRound1Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BigK []byte `protobuf:"bytes,1,opt,name=bigK,proto3" json:"bigK,omitempty"`
}

func (x *SignRound1Message1) Reset() {
	*x = SignRound1Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_eddsa_cmp_onsign_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound1Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound1Message1) ProtoMessage() {}

func (x *SignRound1Message1) ProtoReflect() protoreflect.Message {
	mi := &file_eddsa_cmp_onsign_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound1Message1.ProtoReflect.Descriptor instead.
func (*SignRound1Message1) Descriptor() ([]byte, []int) {
	return file_eddsa_cmp_onsign_proto_rawDescGZIP(), []int{0}
}

func (x *SignRound1Message1) GetBigK() []byte {
	if x != nil {
		return x.BigK
	}
	return nil
}

// Represents a BROADCAST message sent to all parties during Round 1 of the EDDSA TSS signing protocol.
type SignRound1Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EncProof []byte `protobuf:"bytes,1,opt,name=enc_proof,json=encProof,proto3" json:"enc_proof,omitempty"`
}

func (x *SignRound1Message2) Reset() {
	*x = SignRound1Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_eddsa_cmp_onsign_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound1Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound1Message2) ProtoMessage() {}

func (x *SignRound1Message2) ProtoReflect() protoreflect.Message {
	mi := &file_eddsa_cmp_onsign_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound1Message2.ProtoReflect.Descriptor instead.
func (*SignRound1Message2) Descriptor() ([]byte, []int) {
	return file_eddsa_cmp_onsign_proto_rawDescGZIP(), []int{1}
}

func (x *SignRound1Message2) GetEncProof() []byte {
	if x != nil {
		return x.EncProof
	}
	return nil
}

// Represents a P2P message sent to all parties during Round 2 of the EDDSA TSS signing protocol.
type SignRound2Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RX       []byte `protobuf:"bytes,1,opt,name=r_x,json=rX,proto3" json:"r_x,omitempty"`
	RY       []byte `protobuf:"bytes,2,opt,name=r_y,json=rY,proto3" json:"r_y,omitempty"`
	LogProof []byte `protobuf:"bytes,3,opt,name=log_proof,json=logProof,proto3" json:"log_proof,omitempty"`
}

func (x *SignRound2Message) Reset() {
	*x = SignRound2Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_eddsa_cmp_onsign_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound2Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound2Message) ProtoMessage() {}

func (x *SignRound2Message) ProtoReflect() protoreflect.Message {
	mi := &file_eddsa_cmp_onsign_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound2Message.ProtoReflect.Descriptor instead.
func (*SignRound2Message) Descriptor() ([]byte, []int) {
	return file_eddsa_cmp_onsign_proto_rawDescGZIP(), []int{2}
}

func (x *SignRound2Message) GetRX() []byte {
	if x != nil {
		return x.RX
	}
	return nil
}

func (x *SignRound2Message) GetRY() []byte {
	if x != nil {
		return x.RY
	}
	return nil
}

func (x *SignRound2Message) GetLogProof() []byte {
	if x != nil {
		return x.LogProof
	}
	return nil
}

// Represents a P2P message sent to all parties during Round 3 of the EDDSA TSS signing protocol.
type SignRound3Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Sigma []byte `protobuf:"bytes,1,opt,name=sigma,proto3" json:"sigma,omitempty"`
}

func (x *SignRound3Message) Reset() {
	*x = SignRound3Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_eddsa_cmp_onsign_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound3Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound3Message) ProtoMessage() {}

func (x *SignRound3Message) ProtoReflect() protoreflect.Message {
	mi := &file_eddsa_cmp_onsign_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound3Message.ProtoReflect.Descriptor instead.
func (*SignRound3Message) Descriptor() ([]byte, []int) {
	return file_eddsa_cmp_onsign_proto_rawDescGZIP(), []int{3}
}

func (x *SignRound3Message) GetSigma() []byte {
	if x != nil {
		return x.Sigma
	}
	return nil
}

var File_eddsa_cmp_onsign_proto protoreflect.FileDescriptor

var file_eddsa_cmp_onsign_proto_rawDesc = []byte{
	0x0a, 0x16, 0x65, 0x64, 0x64, 0x73, 0x61, 0x2d, 0x63, 0x6d, 0x70, 0x2d, 0x6f, 0x6e, 0x73, 0x69,
	0x67, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1c, 0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63,
	0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e, 0x65, 0x64, 0x64, 0x73, 0x61, 0x2e, 0x73,
	0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x22, 0x28, 0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f,
	0x75, 0x6e, 0x64, 0x31, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x12, 0x0a, 0x04,
	0x62, 0x69, 0x67, 0x4b, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x62, 0x69, 0x67, 0x4b,
	0x22, 0x31, 0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x12, 0x1b, 0x0a, 0x09, 0x65, 0x6e, 0x63, 0x5f, 0x70, 0x72,
	0x6f, 0x6f, 0x66, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x65, 0x6e, 0x63, 0x50, 0x72,
	0x6f, 0x6f, 0x66, 0x22, 0x52, 0x0a, 0x11, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64,
	0x32, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x0f, 0x0a, 0x03, 0x72, 0x5f, 0x78, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x72, 0x58, 0x12, 0x0f, 0x0a, 0x03, 0x72, 0x5f, 0x79,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x72, 0x59, 0x12, 0x1b, 0x0a, 0x09, 0x6c, 0x6f,
	0x67, 0x5f, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x6c,
	0x6f, 0x67, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x22, 0x29, 0x0a, 0x11, 0x53, 0x69, 0x67, 0x6e, 0x52,
	0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x14, 0x0a, 0x05,
	0x73, 0x69, 0x67, 0x6d, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x73, 0x69, 0x67,
	0x6d, 0x61, 0x42, 0x12, 0x5a, 0x10, 0x65, 0x64, 0x64, 0x73, 0x61, 0x5f, 0x63, 0x6d, 0x70, 0x2f,
	0x6f, 0x6e, 0x73, 0x69, 0x67, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_eddsa_cmp_onsign_proto_rawDescOnce sync.Once
	file_eddsa_cmp_onsign_proto_rawDescData = file_eddsa_cmp_onsign_proto_rawDesc
)

func file_eddsa_cmp_onsign_proto_rawDescGZIP() []byte {
	file_eddsa_cmp_onsign_proto_rawDescOnce.Do(func() {
		file_eddsa_cmp_onsign_proto_rawDescData = protoimpl.X.CompressGZIP(file_eddsa_cmp_onsign_proto_rawDescData)
	})
	return file_eddsa_cmp_onsign_proto_rawDescData
}

var file_eddsa_cmp_onsign_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_eddsa_cmp_onsign_proto_goTypes = []interface{}{
	(*SignRound1Message1)(nil), // 0: binance.tsslib.eddsa.signing.SignRound1Message1
	(*SignRound1Message2)(nil), // 1: binance.tsslib.eddsa.signing.SignRound1Message2
	(*SignRound2Message)(nil),  // 2: binance.tsslib.eddsa.signing.SignRound2Message
	(*SignRound3Message)(nil),  // 3: binance.tsslib.eddsa.signing.SignRound3Message
}
var file_eddsa_cmp_onsign_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_eddsa_cmp_onsign_proto_init() }
func file_eddsa_cmp_onsign_proto_init() {
	if File_eddsa_cmp_onsign_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_eddsa_cmp_onsign_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound1Message1); i {
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
		file_eddsa_cmp_onsign_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound1Message2); i {
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
		file_eddsa_cmp_onsign_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound2Message); i {
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
		file_eddsa_cmp_onsign_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound3Message); i {
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
			RawDescriptor: file_eddsa_cmp_onsign_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_eddsa_cmp_onsign_proto_goTypes,
		DependencyIndexes: file_eddsa_cmp_onsign_proto_depIdxs,
		MessageInfos:      file_eddsa_cmp_onsign_proto_msgTypes,
	}.Build()
	File_eddsa_cmp_onsign_proto = out.File
	file_eddsa_cmp_onsign_proto_rawDesc = nil
	file_eddsa_cmp_onsign_proto_goTypes = nil
	file_eddsa_cmp_onsign_proto_depIdxs = nil
}
