package gpg

import (
	"bytes"
	_ "github.com/oleiade/trousseau/crypto"
	"io"
	"os"
)

type GpgFileReader struct{}
type GpgFileWriter struct{}
type GpgFile struct {
	file       *os.File
	passphrase string

	Path       string
	Recipients []string
}

func NewGpgFile(filepath, passphrase string, recipients []string) *GpgFile {
	return &GpgFile{
		Path:       filepath,
		Recipients: recipients,
		passphrase: passphrase,
	}
}

// Open opens the named file for reading.
// If successful, methods on the returned file can be used for reading;
// the associated file descriptor has mode O_RDONLY.
// If there is an error, it will be of type *PathError.
func OpenFile(name string, mode int, passphrase string, recipients []string) (*GpgFile, error) {
	f, err := os.OpenFile(name, mode, 0600)
	if err != nil {
		return nil, err
	}

	gpg := NewGpgFile(name, passphrase, recipients)
	gpg.file = f

	return gpg, nil
}

// Close closes the GpgFile, rendering it unusable for I/O.
// It returns an error, if any.
func (gf *GpgFile) Close() error {
	return gf.file.Close()
}

// ReadAll reads the GpgFile and returns the contents.
// A successful call returns err == nil, not err == EOF. Because ReadAll
// reads the whole file, it does not treat an EOF from Read as an error
// to be reported.
func (gf *GpgFile) ReadAll() (data []byte, err error) {
	// It's a good but not certain bet that FileInfo will tell us exactly how much to
	// read, so let's try it but be prepared for the answer to be wrong.
	var n int64

	if fi, err := gf.file.Stat(); err == nil {
		// Don't preallocate a huge buffer, just in case.
		if size := fi.Size(); size < 1e9 {
			n = size
		}
	}

	encryptedData, err := readAll(gf.file, n+bytes.MinRead)
	if err != nil {
		return nil, err
	}

	// Decrypt store data
	InitCrypto(gSecringFile, gf.passphrase)
	plainData, err := Decrypt(string(encryptedData), gf.passphrase)
	if err != nil {
		return nil, err
	}

	return []byte(plainData), nil
}

func (gf *GpgFile) Write(data []byte) (n int, err error) {
	InitPgp(gPubringFile, gf.Recipients)
	encData := Encrypt(string(data))

	return gf.file.Write([]byte(encData))
}

// readAll reads from r until an error or EOF and returns the data it read
// from the internal buffer allocated with a specified capacity.
func readAll(r io.Reader, capacity int64) (b []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, capacity))

	// If the buffer overflows, we will get bytes.ErrTooLarge.
	// Return that as an error. Any other panic remains.
	defer func() {
		e := recover()
		if e == nil {
			return
		}

		if panicErr, ok := e.(error); ok && panicErr == bytes.ErrTooLarge {
			err = panicErr
		} else {
			panic(e)
		}
	}()

	_, err = buf.ReadFrom(r)

	return buf.Bytes(), err
}
