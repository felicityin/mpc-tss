// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v3.21.4
// source: fac_msg.proto

package facproof

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

type NoSmallFactorMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Salt    []byte `protobuf:"bytes,1,opt,name=salt,proto3" json:"salt,omitempty"`
	P       []byte `protobuf:"bytes,2,opt,name=P,proto3" json:"P,omitempty"`
	Q       []byte `protobuf:"bytes,3,opt,name=Q,proto3" json:"Q,omitempty"`
	A       []byte `protobuf:"bytes,4,opt,name=A,proto3" json:"A,omitempty"`
	B       []byte `protobuf:"bytes,5,opt,name=B,proto3" json:"B,omitempty"`
	T       []byte `protobuf:"bytes,6,opt,name=T,proto3" json:"T,omitempty"`
	Sigma   string `protobuf:"bytes,7,opt,name=sigma,proto3" json:"sigma,omitempty"`
	Z1      string `protobuf:"bytes,8,opt,name=z1,proto3" json:"z1,omitempty"`
	Z2      string `protobuf:"bytes,9,opt,name=z2,proto3" json:"z2,omitempty"`
	W1      string `protobuf:"bytes,10,opt,name=w1,proto3" json:"w1,omitempty"`
	W2      string `protobuf:"bytes,11,opt,name=w2,proto3" json:"w2,omitempty"`
	Vletter string `protobuf:"bytes,12,opt,name=vletter,proto3" json:"vletter,omitempty"`
}

func (x *NoSmallFactorMessage) Reset() {
	*x = NoSmallFactorMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fac_msg_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NoSmallFactorMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NoSmallFactorMessage) ProtoMessage() {}

func (x *NoSmallFactorMessage) ProtoReflect() protoreflect.Message {
	mi := &file_fac_msg_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NoSmallFactorMessage.ProtoReflect.Descriptor instead.
func (*NoSmallFactorMessage) Descriptor() ([]byte, []int) {
	return file_fac_msg_proto_rawDescGZIP(), []int{0}
}

func (x *NoSmallFactorMessage) GetSalt() []byte {
	if x != nil {
		return x.Salt
	}
	return nil
}

func (x *NoSmallFactorMessage) GetP() []byte {
	if x != nil {
		return x.P
	}
	return nil
}

func (x *NoSmallFactorMessage) GetQ() []byte {
	if x != nil {
		return x.Q
	}
	return nil
}

func (x *NoSmallFactorMessage) GetA() []byte {
	if x != nil {
		return x.A
	}
	return nil
}

func (x *NoSmallFactorMessage) GetB() []byte {
	if x != nil {
		return x.B
	}
	return nil
}

func (x *NoSmallFactorMessage) GetT() []byte {
	if x != nil {
		return x.T
	}
	return nil
}

func (x *NoSmallFactorMessage) GetSigma() string {
	if x != nil {
		return x.Sigma
	}
	return ""
}

func (x *NoSmallFactorMessage) GetZ1() string {
	if x != nil {
		return x.Z1
	}
	return ""
}

func (x *NoSmallFactorMessage) GetZ2() string {
	if x != nil {
		return x.Z2
	}
	return ""
}

func (x *NoSmallFactorMessage) GetW1() string {
	if x != nil {
		return x.W1
	}
	return ""
}

func (x *NoSmallFactorMessage) GetW2() string {
	if x != nil {
		return x.W2
	}
	return ""
}

func (x *NoSmallFactorMessage) GetVletter() string {
	if x != nil {
		return x.Vletter
	}
	return ""
}

var File_fac_msg_proto protoreflect.FileDescriptor

var file_fac_msg_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x66, 0x61, 0x63, 0x5f, 0x6d, 0x73, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x1e, 0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e,
	0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e, 0x66, 0x61, 0x63, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x22,
	0xe0, 0x01, 0x0a, 0x14, 0x4e, 0x6f, 0x53, 0x6d, 0x61, 0x6c, 0x6c, 0x46, 0x61, 0x63, 0x74, 0x6f,
	0x72, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x61, 0x6c, 0x74,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x73, 0x61, 0x6c, 0x74, 0x12, 0x0c, 0x0a, 0x01,
	0x50, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x50, 0x12, 0x0c, 0x0a, 0x01, 0x51, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x51, 0x12, 0x0c, 0x0a, 0x01, 0x41, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x01, 0x41, 0x12, 0x0c, 0x0a, 0x01, 0x42, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x01, 0x42, 0x12, 0x0c, 0x0a, 0x01, 0x54, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x01, 0x54, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x69, 0x67, 0x6d, 0x61, 0x18, 0x07, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x73, 0x69, 0x67, 0x6d, 0x61, 0x12, 0x0e, 0x0a, 0x02, 0x7a, 0x31, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x7a, 0x31, 0x12, 0x0e, 0x0a, 0x02, 0x7a, 0x32, 0x18, 0x09,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x7a, 0x32, 0x12, 0x0e, 0x0a, 0x02, 0x77, 0x31, 0x18, 0x0a,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x77, 0x31, 0x12, 0x0e, 0x0a, 0x02, 0x77, 0x32, 0x18, 0x0b,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x77, 0x32, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x6c, 0x65, 0x74,
	0x74, 0x65, 0x72, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x6c, 0x65, 0x74, 0x74,
	0x65, 0x72, 0x42, 0x11, 0x5a, 0x0f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x66, 0x61, 0x63,
	0x70, 0x72, 0x6f, 0x6f, 0x66, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_fac_msg_proto_rawDescOnce sync.Once
	file_fac_msg_proto_rawDescData = file_fac_msg_proto_rawDesc
)

func file_fac_msg_proto_rawDescGZIP() []byte {
	file_fac_msg_proto_rawDescOnce.Do(func() {
		file_fac_msg_proto_rawDescData = protoimpl.X.CompressGZIP(file_fac_msg_proto_rawDescData)
	})
	return file_fac_msg_proto_rawDescData
}

var file_fac_msg_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_fac_msg_proto_goTypes = []interface{}{
	(*NoSmallFactorMessage)(nil), // 0: binance.tsslib.crypto.facproof.NoSmallFactorMessage
}
var file_fac_msg_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_fac_msg_proto_init() }
func file_fac_msg_proto_init() {
	if File_fac_msg_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_fac_msg_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NoSmallFactorMessage); i {
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
			RawDescriptor: file_fac_msg_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_fac_msg_proto_goTypes,
		DependencyIndexes: file_fac_msg_proto_depIdxs,
		MessageInfos:      file_fac_msg_proto_msgTypes,
	}.Build()
	File_fac_msg_proto = out.File
	file_fac_msg_proto_rawDesc = nil
	file_fac_msg_proto_goTypes = nil
	file_fac_msg_proto_depIdxs = nil
}
