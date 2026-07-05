// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"unsafe"

	"github.com/google/sam/mobile/sam-node-ffi/ffi"
)

func main() {}

//export StartNode
func StartNode(configJSON *C.char) *C.char {
	goConfigJSON := C.GoString(configJSON)
	err := ffi.StartNode(goConfigJSON)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export StopNode
func StopNode() *C.char {
	err := ffi.StopNode()
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export GetNodeID
func GetNodeID() *C.char {
	nodeID := ffi.GetNodeID()
	if nodeID != "" {
		return C.CString(nodeID)
	}
	return nil
}

//export EnrollNode
func EnrollNode(dataDir *C.char, hubURL *C.char, jwt *C.char, allowLoopback C.char) *C.char {
	goDataDir := C.GoString(dataDir)
	goHubURL := C.GoString(hubURL)
	goJWT := C.GoString(jwt)
	goAllowLoopback := allowLoopback != 0

	err := ffi.EnrollNode(goDataDir, goHubURL, goJWT, goAllowLoopback)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export FetchHubInfoJSON
func FetchHubInfoJSON(hubURL *C.char) *C.char {
	goHubURL := C.GoString(hubURL)
	jsonStr := ffi.FetchHubInfoJSON(goHubURL)
	return C.CString(jsonStr)
}

//export IsEnrolled
func IsEnrolled(dataDir *C.char) C.char {
	goDataDir := C.GoString(dataDir)
	return C.char(ffi.IsEnrolled(goDataDir))
}

//export GetMeshInfo
func GetMeshInfo() *C.char {
	jsonStr := ffi.GetMeshInfo()
	return C.CString(jsonStr)
}

//export FreeString
func FreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}
