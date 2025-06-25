package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	MagicHeader = "VEIL24"  // The magic header
	KeySize     = 32        // AES-256
	NonceSize   = 12        // GCM nonce size
	HashSize    = 32        // SHA256 hash size
	BufferSize  = 1024 * 1024 // 1MB buffer for large files
)

func main() {
	if len(os.Args) < 2 {
		showHelp()
		return
	}

	operation := os.Args[1]
	
	switch operation {
	case "hide":
		hideCommand()
	case "reveal":
		revealCommand()
	default:
		showHelp()
	}
}

func showHelp() {
	fmt.Println("Veil - A file obfuscation tool to bypass content detection")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  veil hide -i <input_file> -o <output_file>")
	fmt.Println("  veil reveal -i <input_file> [-o <output_path>]")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("  hide      Obfuscate a file (make it unrecognizable)")
	fmt.Println("  reveal    Restore the original file")
	fmt.Println("")
	fmt.Println("Options:")
	fmt.Println("  -i, --input   Input file path")
	fmt.Println("  -o, --output  Output file path (for reveal: file, directory, or empty for current dir)")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  veil hide -i ./movie.mp4 -o ./data.bin")
	fmt.Println("  veil reveal -i ./data.bin")
	fmt.Println("  veil reveal -i ./data.bin -o ./videos/")
	fmt.Println("  veil reveal -i ./data.bin -o ./restored_movie.mp4")
}

func hideCommand() {
	fs := flag.NewFlagSet("hide", flag.ExitOnError)
	input := fs.String("i", "", "Input file path")
	fs.StringVar(input, "input", "", "Input file path")
	output := fs.String("o", "", "Output file path")
	fs.StringVar(output, "output", "", "Output file path")
	
	fs.Parse(os.Args[2:])
	
	if *input == "" || *output == "" {
		fmt.Println("Error: Both input and output files must be specified for hiding")
		fs.Usage()
		return
	}
	
	if err := validateInputFile(*input); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	
	if err := hideFile(*input, *output); err != nil {
		fmt.Printf("Error during file obfuscation: %v\n", err)
		return
	}
	
	fmt.Printf("File hidden successfully: %s -> %s\n", *input, *output)
}

func revealCommand() {
	fs := flag.NewFlagSet("reveal", flag.ExitOnError)
	input := fs.String("i", "", "Input file path")
	fs.StringVar(input, "input", "", "Input file path")
	output := fs.String("o", "", "Output path (file, directory, or empty for current dir)")
	fs.StringVar(output, "output", "", "Output path")
	
	fs.Parse(os.Args[2:])
	
	if *input == "" {
		fmt.Println("Error: Input file must be specified for revealing")
		fs.Usage()
		return
	}
	
	if err := validateInputFile(*input); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	
	outputPath, err := revealFile(*input, *output)
	if err != nil {
		fmt.Printf("Error during file restoration: %v\n", err)
		return
	}
	
	fmt.Printf("File revealed successfully: %s -> %s\n", *input, outputPath)
}

func validateInputFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot access input file: %v", err)
	}
	
	if info.IsDir() {
		return fmt.Errorf("input path is a directory, please provide a file path")
	}
	
	return nil
}

func generateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	return bytes, err
}

func calculateSHA256(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	hash := sha256.New()
	buffer := make([]byte, BufferSize)
	
	for {
		n, err := file.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		hash.Write(buffer[:n])
	}
	
	return hash.Sum(nil), nil
}

func hideFile(inputPath, outputPath string) error {
	fmt.Println("Calculating file hash for integrity verification...")
	
	// Calculate SHA256 of original file
	originalHash, err := calculateSHA256(inputPath)
	if err != nil {
		return fmt.Errorf("failed to calculate file hash: %v", err)
	}
	
	// Open input file
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %v", err)
	}
	defer inputFile.Close()
	
	// Get file info for size tracking
	fileInfo, err := inputFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %v", err)
	}
	
	// Create output file
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outputFile.Close()
	
	// Generate random key and nonce for this obfuscation
	key, err := generateRandomBytes(KeySize)
	if err != nil {
		return fmt.Errorf("failed to generate encryption key: %v", err)
	}
	
	nonce, err := generateRandomBytes(NonceSize)
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %v", err)
	}
	
	// Get original filename
	originalName := filepath.Base(inputPath)
	originalNameBytes := []byte(originalName)
	
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %v", err)
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %v", err)
	}
	
	fmt.Println("Writing obfuscated file header...")
	
	// Write file header
	if _, err := outputFile.Write([]byte(MagicHeader)); err != nil {
		return fmt.Errorf("failed to write magic header: %v", err)
	}
	
	if _, err := outputFile.Write(nonce); err != nil {
		return fmt.Errorf("failed to write nonce: %v", err)
	}
	
	if _, err := outputFile.Write(key); err != nil {
		return fmt.Errorf("failed to write key: %v", err)
	}
	
	if _, err := outputFile.Write(originalHash); err != nil {
		return fmt.Errorf("failed to write file hash: %v", err)
	}
	
	nameLen := uint32(len(originalNameBytes))
	if err := binary.Write(outputFile, binary.LittleEndian, nameLen); err != nil {
		return fmt.Errorf("failed to write filename length: %v", err)
	}
	
	if _, err := outputFile.Write(originalNameBytes); err != nil {
		return fmt.Errorf("failed to write filename: %v", err)
	}
	
	fileSize := uint64(fileInfo.Size())
	if err := binary.Write(outputFile, binary.LittleEndian, fileSize); err != nil {
		return fmt.Errorf("failed to write file size: %v", err)
	}
	
	fmt.Println("Obfuscating file content...")
	
	// Process file in chunks
	buffer := make([]byte, BufferSize)
	chunkIndex := int64(0)
	totalProcessed := int64(0)
	
	for {
		n, err := inputFile.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read input file: %v", err)
		}
		
		// Create unique nonce for each chunk
		chunkNonce := make([]byte, NonceSize)
		copy(chunkNonce, nonce)
		
		for i := 0; i < 8 && i < NonceSize; i++ {
			chunkNonce[i] ^= byte(chunkIndex >> (i * 8))
		}
		
		// Encrypt the chunk
		chunk := buffer[:n]
		encrypted := gcm.Seal(nil, chunkNonce, chunk, nil)
		
		// Write chunk
		chunkSize := uint32(len(encrypted))
		if err := binary.Write(outputFile, binary.LittleEndian, chunkSize); err != nil {
			return fmt.Errorf("failed to write chunk size: %v", err)
		}
		
		if _, err := outputFile.Write(encrypted); err != nil {
			return fmt.Errorf("failed to write encrypted chunk: %v", err)
		}
		
		chunkIndex++
		totalProcessed += int64(n)
		
		if fileSize > 10*1024*1024 {
			progress := float64(totalProcessed) / float64(fileSize) * 100
			fmt.Printf("\rProgress: %.1f%% (%d/%d bytes)", progress, totalProcessed, fileSize)
		}
	}
	
	if fileSize > 10*1024*1024 {
		fmt.Println()
	}
	
	// Write EOF marker
	if err := binary.Write(outputFile, binary.LittleEndian, uint32(0)); err != nil {
		return fmt.Errorf("failed to write EOF marker: %v", err)
	}
	
	return nil
}

func revealFile(inputPath, outputPath string) (string, error) {
	// Open input file
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return "", fmt.Errorf("failed to open input file: %v", err)
	}
	defer inputFile.Close()
	
	fmt.Println("Reading obfuscated file header...")
	
	// Read and validate magic header
	magic := make([]byte, len(MagicHeader))
	if _, err := inputFile.Read(magic); err != nil {
		return "", fmt.Errorf("failed to read magic header: %v", err)
	}
	
	if string(magic) != MagicHeader {
		return "", fmt.Errorf("invalid file format: not a veil obfuscated file")
	}
	
	// Read nonce
	nonce := make([]byte, NonceSize)
	if _, err := inputFile.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to read nonce: %v", err)
	}
	
	// Read embedded key
	key := make([]byte, KeySize)
	if _, err := inputFile.Read(key); err != nil {
		return "", fmt.Errorf("failed to read key: %v", err)
	}
	
	// Read original file hash
	originalHash := make([]byte, HashSize)
	if _, err := inputFile.Read(originalHash); err != nil {
		return "", fmt.Errorf("failed to read file hash: %v", err)
	}
	
	// Read original filename length
	var nameLen uint32
	if err := binary.Read(inputFile, binary.LittleEndian, &nameLen); err != nil {
		return "", fmt.Errorf("failed to read filename length: %v", err)
	}
	
	if nameLen == 0 || nameLen > 1024 {
		return "", fmt.Errorf("invalid filename length: %d", nameLen)
	}
	
	// Read original filename
	nameBytes := make([]byte, nameLen)
	if _, err := inputFile.Read(nameBytes); err != nil {
		return "", fmt.Errorf("failed to read filename: %v", err)
	}
	
	originalName := string(nameBytes)
	
	// Read original file size
	var originalSize uint64
	if err := binary.Read(inputFile, binary.LittleEndian, &originalSize); err != nil {
		return "", fmt.Errorf("failed to read original file size: %v", err)
	}
	
	// Determine output path
	finalOutputPath, err := determineOutputPath(outputPath, originalName)
	if err != nil {
		return "", err
	}
	
	// Create output file
	outputFile, err := os.Create(finalOutputPath)
	if err != nil {
		return "", fmt.Errorf("failed to create output file: %v", err)
	}
	defer outputFile.Close()
	
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}
	
	fmt.Println("Revealing file content...")
	
	// Decrypt file content chunk by chunk
	totalDecrypted := int64(0)
	chunkIndex := int64(0)
	
	for totalDecrypted < int64(originalSize) {
		// Read chunk size
		var chunkSize uint32
		if err := binary.Read(inputFile, binary.LittleEndian, &chunkSize); err != nil {
			if err == io.EOF {
				return "", fmt.Errorf("unexpected end of file")
			}
			return "", fmt.Errorf("failed to read chunk size: %v", err)
		}
		
		if chunkSize == 0 {
			break
		}
		
		if chunkSize > BufferSize*2 {
			return "", fmt.Errorf("invalid chunk size: %d", chunkSize)
		}
		
		// Read encrypted chunk
		encryptedChunk := make([]byte, chunkSize)
		if _, err := inputFile.Read(encryptedChunk); err != nil {
			return "", fmt.Errorf("failed to read encrypted chunk: %v", err)
		}
		
		// Recreate chunk nonce
		chunkNonce := make([]byte, NonceSize)
		copy(chunkNonce, nonce)
		
		for i := 0; i < 8 && i < NonceSize; i++ {
			chunkNonce[i] ^= byte(chunkIndex >> (i * 8))
		}
		
		// Decrypt chunk
		decrypted, err := gcm.Open(nil, chunkNonce, encryptedChunk, nil)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt chunk %d: %v", chunkIndex, err)
		}
		
		// Handle last chunk truncation
		writeSize := len(decrypted)
		if totalDecrypted+int64(writeSize) > int64(originalSize) {
			writeSize = int(int64(originalSize) - totalDecrypted)
		}
		
		// Write decrypted data
		if _, err := outputFile.Write(decrypted[:writeSize]); err != nil {
			return "", fmt.Errorf("failed to write decrypted data: %v", err)
		}
		
		totalDecrypted += int64(writeSize)
		chunkIndex++
		
		if originalSize > 10*1024*1024 {
			progress := float64(totalDecrypted) / float64(originalSize) * 100
			fmt.Printf("\rProgress: %.1f%% (%d/%d bytes)", progress, totalDecrypted, originalSize)
		}
	}
	
	if originalSize > 10*1024*1024 {
		fmt.Println()
	}
	
	// Verify size
	if totalDecrypted != int64(originalSize) {
		return "", fmt.Errorf("size mismatch: expected %d bytes, got %d bytes", originalSize, totalDecrypted)
	}
	
	outputFile.Close()
	
	fmt.Println("Verifying file integrity...")
	
	// Verify hash
	decryptedHash, err := calculateSHA256(finalOutputPath)
	if err != nil {
		return "", fmt.Errorf("failed to calculate decrypted file hash: %v", err)
	}
	
	if !compareHashes(originalHash, decryptedHash) {
		os.Remove(finalOutputPath)
		return "", fmt.Errorf("file integrity verification failed: hash mismatch")
	}
	
	fmt.Println("File integrity verified successfully!")
	
	return finalOutputPath, nil
}

func compareHashes(hash1, hash2 []byte) bool {
	if len(hash1) != len(hash2) {
		return false
	}
	
	for i := range hash1 {
		if hash1[i] != hash2[i] {
			return false
		}
	}
	
	return true
}

func determineOutputPath(outputPath, originalName string) (string, error) {
	if outputPath == "" {
		return originalName, nil
	}
	
	info, err := os.Stat(outputPath)
	if err != nil {
		return outputPath, nil
	}
	
	if info.IsDir() {
		return filepath.Join(outputPath, originalName), nil
	}
	
	return outputPath, nil
}
