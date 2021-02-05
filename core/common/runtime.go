package common

import (
	"path"
	"runtime"
	"strconv"
)

// FileLoc 获取该函数被调用时的文件路径和行号，如("/a/b/c.go", 123)
func FileLoc() (string, int) {
	file, line := "???", 0
	if _, f, l, ok := runtime.Caller(1); ok {
		file, line = f, l
	}
	return file, line
}

// FileLocStr 获取该函数被调用时的文件名和行号，如"c.go:123"
func FileLocStr() string {
	file, line := "???", 0
	if _, f, l, ok := runtime.Caller(1); ok {
		file, line = f, l
	}
	file = path.Base(file) + ":"
	return file + strconv.Itoa(line)
}
