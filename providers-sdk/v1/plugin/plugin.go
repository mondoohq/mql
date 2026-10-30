// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import llx "go.mondoo.com/mql/llx"

//go:generate protoc --plugin=protoc-gen-go=../../../scripts/protoc/protoc-gen-go --plugin=protoc-gen-go-grpc=../../../scripts/protoc/protoc-gen-go-grpc --plugin=protoc-gen-go-vtproto=../../../scripts/protoc/protoc-gen-go-vtproto --proto_path=../../../:. --go_out=. --go_opt=paths=source_relative  --go-grpc_out=. --go-grpc_opt=paths=source_relative --go-vtproto_opt=paths=source_relative --go-vtproto_out=. --go-vtproto_opt=features=marshal+unmarshal+size+clone plugin.proto

// ParseArgsFun is a function to take a list of incoming arguments and parse
// them. This is used for 3 possible use-cases:
//
//  1. Arguments get transformed.
//     eg: sshd.config(path: ..) => turn the path into the file field
//     here we return the new set of arguments, ie:
//     in: {"path": ..}
//     out: {"file": file(..)}
//
//  2. Arguments lead to a resource lookup
//     eg: user(name: "bob") => look up the user with this name.
//     here we use the argument to look up the resource ie:
//     in: {"name": "bob"}  ==> call users.list and find the user
//     out: the user(..) object that was previously initialized by users.list
//
//  3. Arguments lead to additional processing and pre-caching.
//     eg: service.field(id: ..)  => needs to call the API to get the object
//     since we don't want to do this twice, we initialize the object
//     right during argument processing and return it.
//     in: {"id": ..}  ==> calls I/O, then creates the new object
//     out: service.field which is fully initialized
//     NOTE: please remember to initialize all arguments that are provided
//     by users, since you have to return a complete object
type ParseArgsFun func(runtime *Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, Resource, error)

// CreateResource is an auto-generated method to create a resource.
// It takes a list of arguments from which the resource is initialized.
// (Note: if necessary, parse arguments beforehand).
type CreateResource func(runtime *Runtime, args map[string]*llx.RawData) (Resource, error)

// ResourceFactory is generated for every resource and helps to initialize it
// and parse its arguments. This is focused on everything that is done
// within a plugin, not beyond (recording, upstream etc).
type ResourceFactory struct {
	Init   ParseArgsFun
	Create CreateResource
}
