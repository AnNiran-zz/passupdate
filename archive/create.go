package archive

import (
	"archive/zip"
	"io"
	"os"
)

// CreateArchive creates a new archive and add files to it 
// archive filename is set in config to `users.db`
// files added on success from encsrc/<mode-name> directory are:
// key
// cipher
// payload
func CreateArchive(filenames []string) error {
	archivePointer, err := createArchive()
	if err != nil {
		return err
	}

	// Write to the newly created file using the Reader/Writer interface
	archiveWriter := zip.NewWriter(archivePointer)
	defer archiveWriter.Close()

	for _, file := range filenames {
		if err = acrhiveFile(archiveWriter, file); err != nil {
			return err
		}
	}

	return nil
}

// archiveFile adds a file to an archive using its pointe
func acrhiveFile(archiveWriter *zip.Writer, filename string) error {
	fpath, err := readFile(filename)
	if err != nil {
		return err
	}
	
	fileToAdd, err := os.Open(fpath)
	if err != nil {
		return err
	}
	defer fileToAdd.Close()

	// Get file info and set up the header
	info, err := fileToAdd.Stat()
	if err != nil {
		return err
	}

	fHeader, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}

	fHeader.Method = zip.Deflate
	writer, err := archiveWriter.CreateHeader(fHeader)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, fileToAdd)
	return err
}


