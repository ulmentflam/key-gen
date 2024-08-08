package save

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"golang.org/x/crypto/pbkdf2"

	"key-gen/bip44"
	"key-gen/util"
)

const HiddenFile = ".key-gen"
const PwSaltBytes = 32
const EncryptionIterations = 4096
const KeyBits = 32

type FSSaver struct {
	filePath string
}

func NewFileSystemSaver(config util.KeyConfig) (*FSSaver, error) {
	if config.GlobalConfig.FilePath != "" {
		err := upsertPath(config.GlobalConfig.FilePath)
		if err != nil {
			return nil, err
		}
		return &FSSaver{config.GlobalConfig.FilePath}, nil
	}
	filePath, err := keyGenPath()
	if err != nil {
		return nil, err
	}
	err = upsertPath(*filePath)
	if err != nil {
		return nil, err
	}
	return &FSSaver{*filePath}, nil
}

func Decrypt(filePath string, password string) ([]byte, error) {
	salt := make([]byte, PwSaltBytes)
	key := pbkdf2.Key([]byte(password), salt, EncryptionIterations, KeyBits, sha256.New)
	// Reading ciphertext file
	cipherText, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Creating block of algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Creating GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Remove nonce and decrypt
	nonce := cipherText[:gcm.NonceSize()]
	cipherText = cipherText[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func (s *FSSaver) Save(ctx context.Context, config util.KeyConfig, manager *bip44.KeyManager) error {
	currentTime := time.Now()
	fileExt := ".json"
	if config.Encrypt {
		fileExt = ".bin"
	}
	fileName := s.filePath + "/" + strings.ReplaceAll(fmt.Sprintf("%s %s", config.Name, currentTime.Format(time.RFC3339)), " ", "-") + fileExt
	fmt.Printf("\n%-18s \n", "File System")
	fmt.Println(strings.Repeat("-", 106))
	fmt.Printf("%-18s %s\n", "File Path:", s.filePath)

	jsn, err := manager.ToJSON(config.Accounts, config.Compressed)
	if err != nil {
		return err
	}

	text := []byte(jsn)

	if config.Encrypt {
		fmt.Printf("\n%-18s %s\n\n", "Encrypted:", "AES-256-GCM")
		password := config.GlobalConfig.Password
		salt := make([]byte, PwSaltBytes)
		dk := pbkdf2.Key([]byte(password), salt, EncryptionIterations, KeyBits, sha256.New)

		// Creating block of algorithm
		block, err := aes.NewCipher(dk)
		if err != nil {
			panic(err)
		}

		// Creating GCM mode
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err)
		}

		// Generating random nonce
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			panic(err)
		}

		// Encrypt file
		text = gcm.Seal(nonce, nonce, text, nil)
	}

	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			log.Error("Error closing file", "error", err)
		}
	}(f)

	_, err = f.Write(text)
	if err != nil {
		return err
	}
	fmt.Printf("%-18s %s\n", "File Name:", fileName)

	return nil
}

func upsertPath(path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err = os.Mkdir(path, os.ModePerm)
		if err != nil {
			return err
		}
	}
	return nil
}
func keyGenPath() (*string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := home + "/" + HiddenFile
	return &path, nil
}
