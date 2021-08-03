/*
Copyright © 2021 SYLVAIN AFCHAIN

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ebpfkit

import (
	"fmt"
	"os"
	"path"
	"strings"
)

// fs actions
const (
	FaKMsgAction            uint64 = 1
	FaOverrideContentAction uint64 = 2
	FaOverrideReturnAction  uint64 = 4
	FaHideFileAction        uint64 = 8
	FaAppendContentAction   uint64 = 16
)

// progs
const (
	FaKMsgProg = iota + FaKMsgAction
	FaOverrideContentProg

	FaFillWithZeroProg     = 10
	FaOverrideGetDentsProg = 11
)

type FaFdContentKey struct {
	ID    uint64
	Chunk uint32
}

// Write write binary representation
func (p *FaFdContentKey) Write(buffer []byte) {
	ByteOrder.PutUint64(buffer[0:8], p.ID)
	ByteOrder.PutUint32(buffer[8:12], p.Chunk)
}

// Bytes returns array of byte representation
func (p *FaFdContentKey) Bytes() []byte {
	b := make([]byte, 16)
	p.Write(b)
	return b
}

type FaFdContent struct {
	Size    uint64
	Content [64]byte
}

// Write write binary representation
func (p *FaFdContent) Write(buffer []byte) {
	ByteOrder.PutUint64(buffer[0:8], p.Size)
	copy(buffer[8:], p.Content[:])
}

// Bytes returns array of byte representation
func (p *FaFdContent) Bytes() []byte {
	b := make([]byte, len(p.Content)+8)
	p.Write(b)
	return b
}

type FaFdKey struct {
	Fd  uint64
	Pid uint32
}

// Write write binary representation
func (p *FaFdKey) Write(buffer []byte) {
	ByteOrder.PutUint64(buffer[0:8], p.Fd)
	ByteOrder.PutUint32(buffer[8:12], p.Pid)
}

// Bytes returns array of byte representation
func (p *FaFdKey) Bytes() []byte {
	b := make([]byte, 16)
	p.Write(b)
	return b
}

// FaFdAttr represents a file
type FaFdAttr struct {
	Action      uint64
	ReturnValue int64
}

// Write write binary representation
func (p *FaFdAttr) Write(buffer []byte) {
	ByteOrder.PutUint64(buffer[0:8], p.Action)
	ByteOrder.PutUint64(buffer[8:16], uint64(p.ReturnValue))
}

// Bytes returns array of byte representation
func (p *FaFdAttr) Bytes() []byte {
	b := make([]byte, 64)
	p.Write(b)
	return b
}

// FaPathKey represents a path node used to match in-kernel path
type FaPathKey struct {
	Path string
	Pos  uint64
}

// Write write binary representation
func (p *FaPathKey) Write(buffer []byte) {
	hash := FNVHashStr(p.Path)
	ByteOrder.PutUint64(buffer[0:8], hash)
	ByteOrder.PutUint64(buffer[8:16], p.Pos)
}

// Bytes returns array of byte representation
func (p *FaPathKey) Bytes() []byte {
	b := make([]byte, 16)
	p.Write(b)
	return b
}

func (p *FaPathKey) String() string {
	return fmt.Sprintf("Path: %s, Pos: %d, Hash: %d", p.Path, p.Pos, FNVHashStr(p.Path))
}

// FsPathKeys returns a list of FsPathKey for the given path
func FaPathKeys(s string) []FaPathKey {
	var keys []FaPathKey

	els := strings.Split(s, "/")

	if len(els) > 0 {
		if els[0] == "" {
			els[0] = "/"
		}
		if els[len(els)-1] == "" {
			els = els[:len(els)-1]
		}
	}
	last := len(els) - 1

	for i, el := range els {
		keys = append(keys, FaPathKey{
			Path: el,
			Pos:  uint64(last - i),
		})
	}

	return keys
}

// FaPathAttr represents attr to apply for a path
type FaPathAttr struct {
	FSType      string
	Action      uint64
	OverrideID  uint64
	ReturnValue int64
	HiddenHash  uint64
	Comm        string
}

// Write write binary representation
func (p *FaPathAttr) Write(buffer []byte) {
	var fsHash uint64
	if p.FSType != "" {
		fsHash = FNVHashStr(p.FSType)
	}

	var commHash uint64
	if p.Comm != "" {
		commHash = FNVHashStr(p.Comm)
	}

	ByteOrder.PutUint64(buffer[0:8], fsHash)
	ByteOrder.PutUint64(buffer[8:16], commHash)
	ByteOrder.PutUint64(buffer[16:24], p.Action)
	ByteOrder.PutUint64(buffer[24:32], uint64(p.ReturnValue))
	ByteOrder.PutUint64(buffer[32:40], p.OverrideID)
	ByteOrder.PutUint64(buffer[40:48], p.HiddenHash)
}

// Bytes returns array of byte representation
func (p *FaPathAttr) Bytes() []byte {
	b := make([]byte, 48)
	p.Write(b)
	return b
}

func (p *FaPathAttr) String() string {
	return fmt.Sprintf("FSType: %s, Hash: %d", p.FSType, FNVHashStr(p.FSType))
}

func GetExeHash() uint64 {
	exe, _ := os.Executable()
	return FNVHashStr(path.Base(exe))
}
