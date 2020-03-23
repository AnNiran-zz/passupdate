package archive

// ExtractData checks if destination path to /rsc/<mode>/<archive-name> exists
// and extract contained files in the same directory
// <archive-name> is sent in package configuration and must be present to run the functionality
func ExtractData() ([]string, error) {
	// extract content in respective destination
	filenames, err := extractZip()
	if err != nil {
		return nil, err
	}

	return filenames, nil
}