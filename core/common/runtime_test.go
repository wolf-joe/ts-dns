package common

import (
	"fmt"
	"testing"
)

func TestFileLoc(t *testing.T) {
	fmt.Println(FileLoc())
	fmt.Println(FileLocStr())
}
