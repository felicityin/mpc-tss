// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v3.21.4
// source: log_msg.proto

package logproof

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

type LogStarMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Salt []byte `protobuf:"bytes,1,opt,name=salt,proto3" json:"salt,omitempty"`
	S    []byte `protobuf:"bytes,2,opt,name=S,proto3" json:"S,omitempty"`
	A    []byte `protobuf:"bytes,3,opt,name=A,proto3" json:"A,omitempty"`
	Yx   []byte `protobuf:"bytes,4,opt,name=Yx,proto3" json:"Yx,omitempty"`
	Yy   []byte `protobuf:"bytes,5,opt,name=Yy,proto3" json:"Yy,omitempty"`
	D    []byte `protobuf:"bytes,6,opt,name=D,proto3" json:"D,omitempty"`
	Z1   string `protobuf:"bytes,7,opt,name=z1,proto3" json:"z1,omitempty"`
	Z2   []byte `protobuf:"bytes,8,opt,name=z2,proto3" json:"z2,omitempty"`
	Z3   string `protobuf:"bytes,9,opt,name=z3,proto3" json:"z3,omitempty"`
}

func (x *LogStarMessage) Reset() {
	*x = LogStarMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_log_msg_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LogStarMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogStarMessage) ProtoMessage() {}

func (x *LogStarMessage) ProtoReflect() protoreflect.Message {
	mi := &file_log_msg_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogStarMessage.ProtoReflect.Descriptor instead.
func (*LogStarMessage) Descriptor() ([]byte, []int) {
	return file_log_msg_proto_rawDescGZIP(), []int{0}
}

func (x *LogStarMessage) GetSalt() []byte {
	if x != nil {
		return x.Salt
	}
	return nil
}

func (x *LogStarMessage) GetS() []byte {
	if x != nil {
		return x.S
	}
	return nil
}

func (x *LogStarMessage) GetA() []byte {
	if x != nil {
		return x.A
	}
	return nil
}

func (x *LogStarMessage) GetYx() []byte {
	if x != nil {
		return x.Yx
	}
	return nil
}

func (x *LogStarMessage) GetYy() []byte {
	if x != nil {
		return x.Yy
	}
	return nil
}

func (x *LogStarMessage) GetD() []byte {
	if x != nil {
		return x.D
	}
	return nil
}

func (x *LogStarMessage) GetZ1() string {
	if x != nil {
		return x.Z1
	}
	return ""
}

func (x *LogStarMessage) GetZ2() []byte {
	if x != nil {
		return x.Z2
	}
	return nil
}

func (x *LogStarMessage) GetZ3() string {
	if x != nil {
		return x.Z3
	}
	return ""
}

var File_log_msg_proto protoreflect.FileDescriptor

var file_log_msg_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x6c, 0x6f, 0x67, 0x5f, 0x6d, 0x73, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x15, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e, 0x6c,
	0x6f, 0x67, 0x72, 0x6f, 0x6f, 0x66, 0x22, 0x9e, 0x01, 0x0a, 0x0e, 0x4c, 0x6f, 0x67, 0x53, 0x74,
	0x61, 0x72, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x61, 0x6c,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x73, 0x61, 0x6c, 0x74, 0x12, 0x0c, 0x0a,
	0x01, 0x53, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x53, 0x12, 0x0c, 0x0a, 0x01, 0x41,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x41, 0x12, 0x0e, 0x0a, 0x02, 0x59, 0x78, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x59, 0x78, 0x12, 0x0e, 0x0a, 0x02, 0x59, 0x79, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x59, 0x79, 0x12, 0x0c, 0x0a, 0x01, 0x44, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x44, 0x12, 0x0e, 0x0a, 0x02, 0x7a, 0x31, 0x18, 0x07, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x02, 0x7a, 0x31, 0x12, 0x0e, 0x0a, 0x02, 0x7a, 0x32, 0x18, 0x08, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x02, 0x7a, 0x32, 0x12, 0x0e, 0x0a, 0x02, 0x7a, 0x33, 0x18, 0x09, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x02, 0x7a, 0x33, 0x42, 0x11, 0x5a, 0x0f, 0x63, 0x72, 0x79, 0x70, 0x74,
	0x6f, 0x2f, 0x6c, 0x6f, 0x67, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_log_msg_proto_rawDescOnce sync.Once
	file_log_msg_proto_rawDescData = file_log_msg_proto_rawDesc
)

func file_log_msg_proto_rawDescGZIP() []byte {
	file_log_msg_proto_rawDescOnce.Do(func() {
		file_log_msg_proto_rawDescData = protoimpl.X.CompressGZIP(file_log_msg_proto_rawDescData)
	})
	return file_log_msg_proto_rawDescData
}

var file_log_msg_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_log_msg_proto_goTypes = []interface{}{
	(*LogStarMessage)(nil), // 0: tsslib.crypto.logroof.LogStarMessage
}
var file_log_msg_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_log_msg_proto_init() }
func file_log_msg_proto_init() {
	if File_log_msg_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_log_msg_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LogStarMessage); i {
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
			RawDescriptor: file_log_msg_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_log_msg_proto_goTypes,
		DependencyIndexes: file_log_msg_proto_depIdxs,
		MessageInfos:      file_log_msg_proto_msgTypes,
	}.Build()
	File_log_msg_proto = out.File
	file_log_msg_proto_rawDesc = nil
	file_log_msg_proto_goTypes = nil
	file_log_msg_proto_depIdxs = nil
}
