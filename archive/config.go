package archive

import (
	"fmt"
)

// Mode of operation
// `test` - decrypt/ecrypt content and update password inside /rsc/test
// `standard` - decrypt/encrypt content and update password inside /rsc/standard
var Mode = "test"

// Errors
var (
	ErrFileNonExistent = func(filename string) error {
		return fmt.Errorf("Filename path does not exist: %s", filename)
	}
	ErrIllegalPath = func(path string) error { 
		return fmt.Errorf("Illegal path provided: %s", path)
	}
)

// Filepaths
var ArchiveName = "users.db"
var EncSrcPath  = "encsrc"
