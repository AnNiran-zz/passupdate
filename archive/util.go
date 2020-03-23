package archive

import (
	"os"
	"io"
	"path/filepath"
	"archive/zip"
	"strings"
)

// readFile is used to access archive containing encrypted/decrypted data
// inside /rsc/<mode> directory
func readFile(filename string) (string, error) {
	var filePath string

	workPath, err := os.Getwd()
	if err != nil {
		return filePath, err
	}

	filePath = filepath.Join(workPath, EncSrcPath, Mode, filename)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return filePath, ErrFileNonExistent(filename)
	}
	return filePath, nil
}

// extractZip extracts file content from the achive
// and create new files, replacing the old ones
func extractZip() ([]string, error) {
	var filenames []string

	workPath, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	archive := filepath.Join(workPath, EncSrcPath, Mode, ArchiveName)
	src, err := zip.OpenReader(archive)
	if err != nil {
		return filenames, err
	}
	defer src.Close()

	// 
	for _, file := range src.File {
		// set future file path and check for ZipSlip
		fpath := filepath.Join(archive, file.Name)
		path := filepath.Join(workPath, EncSrcPath, Mode)
		
		if !strings.HasPrefix(fpath, filepath.Clean(archive)+string(os.PathSeparator)) {
			return filenames, ErrIllegalPath(fpath)
		}

		filenames = append(filenames, file.Name)
		if file.FileInfo().IsDir() {
			os.MkdirAll(path, os.ModePerm)
			continue
		}

		// Create the file path if it does not exist
		if err = os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
			return filenames, err
		}

		exitFile, err := os.OpenFile(filepath.Join(path, file.Name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return filenames, err
		}

		rsc, err := file.Open()
		if err != nil {
			return filenames, err
		}

		_, err = io.Copy(exitFile, rsc)
		exitFile.Close() // improve
		rsc.Close()

		if err != nil {
			return filenames, err
		}
	}
	
	return filenames, nil
}

// createArchive creates a new archive containing the specific files
// according to the set mode
// returns the file pointer when successful
func createArchive() (*os.File, error) {
	workPath, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	// Access file and replace content
	// we do not need to check if the file exists here because we do not depend 
	// on its content anymore
	// new file will be created if none exists
	file, err := os.OpenFile(filepath.Join(workPath, EncSrcPath, Mode, ArchiveName), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}
	return file, nil
}
