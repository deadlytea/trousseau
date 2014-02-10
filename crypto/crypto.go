package crypto

import "io"

type EncryptedReader interface {
    io.Reader
    Decrypt(enc []byte) (n int, err error)
}

type EncryptedWriter interface {
    io.Writer
    Encrypt(plain []byte) (n int, err error)
}

type EncryptedReadWriter interface {
    EncryptedReader
    EncryptedWriter
}
