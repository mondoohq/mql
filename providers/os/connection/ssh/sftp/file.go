// Copyright © 2015 Jerry Jacobs <jerry.jacobs@xor-gate.org>.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sftp

import (
	"errors"
	"fmt"
	"os"

	"github.com/pkg/sftp"
)

type File struct {
	fd *sftp.File
	c  *sftp.Client
}

func FileOpen(s *sftp.Client, name string) (*File, error) {
	fd, err := s.Open(name)
	if err != nil {
		return &File{}, err
	}
	return &File{
		fd: fd,
		c:  s,
	}, nil
}

func FileCreate(s *sftp.Client, name string) (*File, error) {
	fd, err := s.Create(name)
	if err != nil {
		return &File{}, err
	}
	return &File{
		fd: fd,
		c:  s,
	}, nil
}

func (f *File) Close() error {
	if f != nil && f.fd != nil {
		return f.fd.Close()
	}
	return nil
}

func (f *File) Name() string {
	if f != nil && f.fd != nil {
		return f.fd.Name()
	}
	return ""
}

func (f *File) Stat() (os.FileInfo, error) {
	if f != nil && f.fd != nil {
		return f.fd.Stat()
	}
	return nil, errors.New("cannot access file")
}

func (f *File) Sync() error {
	return nil
}

func (f *File) Truncate(size int64) error {
	return f.fd.Truncate(size)
}

func (f *File) Read(b []byte) (n int, err error) {
	return f.fd.Read(b)
}

// TODO
func (f *File) ReadAt(b []byte, off int64) (n int, err error) {
	return 0, errors.New("not implemented")
}

func (f *File) Readdir(count int) (res []os.FileInfo, err error) {
	return f.c.ReadDir(f.Name())
}

func (f *File) Readdirnames(n int) (names []string, err error) {
	dirFileInfos, err := f.c.ReadDir(f.Name())
	if err != nil {
		return nil, fmt.Errorf("ssh> could not read dirnames: %v", err)
	}

	dir := make([]string, len(dirFileInfos))
	for i := range dirFileInfos {
		dir[i] = dirFileInfos[i].Name()
	}
	return dir, nil
}

func (f *File) Seek(offset int64, whence int) (int64, error) {
	return f.fd.Seek(offset, whence)
}

func (f *File) Write(b []byte) (n int, err error) {
	return f.fd.Write(b)
}

// TODO
func (f *File) WriteAt(b []byte, off int64) (n int, err error) {
	return 0, errors.New("not implemented")
}

func (f *File) WriteString(s string) (ret int, err error) {
	return f.fd.Write([]byte(s))
}
