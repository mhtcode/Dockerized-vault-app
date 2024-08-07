package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"sync"

	vault "github.com/hashicorp/vault/api"
)

// SecretStore defines the interface for storing and retrieving secrets.
type SecretStore interface {
	Put(ctx context.Context, key string, secret map[string]interface{}) error
	Get(ctx context.Context, key string) (map[string]interface{}, error)
}

// VaultSecretStore is the implementation of SecretStore using HashiCorp Vault.
type VaultSecretStore struct {
	client *vault.Client
}

// NewVaultSecretStore creates a new instance of VaultSecretStore.
func NewVaultSecretStore(address, token string) (*VaultSecretStore, error) {
	config := vault.DefaultConfig()
	config.Address = address

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}

	client.SetToken(token)
	return &VaultSecretStore{client: client}, nil
}

// Put writes a secret to HashiCorp Vault.
func (s *VaultSecretStore) Put(ctx context.Context, key string, secret map[string]interface{}) error {
	// Encrypt the secret value
	if val, ok := secret["value"].(string); ok {
		fmt.Println("\n\n\nVALUE IS:", val)
		encryptedVal, err := encryptValue(val)
		if err != nil {
			return err
		}
		secret["value"] = encryptedVal
	}
	_, err := s.client.KVv2("secret").Put(ctx, key, secret)
	return err
}

// Get reads a secret from HashiCorp Vault.
func (s *VaultSecretStore) Get(ctx context.Context, key string) (map[string]interface{}, error) {
	secret, err := s.client.KVv2("secret").Get(ctx, key)
	if err != nil {
		return nil, err
	}
	// Decrypt the secret value
	if val, ok := secret.Data["value"].(string); ok {
		decryptedVal, err := decryptValue(val)
		if err != nil {
			return nil, err
		}
		secret.Data["value"] = decryptedVal
	}
	return secret.Data, nil
}

// InMemorySecretStore is the implementation of SecretStore using an in-memory map.
type InMemorySecretStore struct {
	secrets map[string]map[string]interface{}
	mu      sync.RWMutex
}

// NewInMemorySecretStore creates a new instance of InMemorySecretStore.
func NewInMemorySecretStore() *InMemorySecretStore {
	return &InMemorySecretStore{
		secrets: make(map[string]map[string]interface{}),
	}
}

// Put writes a secret to the in-memory map and a text file.
func (s *InMemorySecretStore) Put(ctx context.Context, key string, secret map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Convert the secret map to JSON and encrypt it
	jsonSecret, err := json.Marshal(secret)
	if err != nil {
		return err
	}
	encryptedVal, err := encryptValue(string(jsonSecret))
	if err != nil {
		return err
	}
	secretData := map[string]interface{}{
		"value": encryptedVal,
	}
	s.secrets[key] = secretData

	// Write the encrypted secret to a text file
	err = ioutil.WriteFile(fmt.Sprintf("%s.txt", key), []byte(encryptedVal), 0644)
	if err != nil {
		return err
	}

	return nil
}

// Get reads a secret from the in-memory map or the text file.
func (s *InMemorySecretStore) Get(ctx context.Context, key string) (map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	secret, exists := s.secrets[key]
	if !exists {
		// If the secret is not found in the map, try to read it from the text file
		encryptedVal, err := ioutil.ReadFile(fmt.Sprintf("%s.txt", key))
		if err != nil {
			return nil, fmt.Errorf("secret not found")
		}
		// Decrypt the secret value and convert it back to a map
		decryptedVal, err := decryptValue(string(encryptedVal))
		if err != nil {
			return nil, err
		}
		var secretMap map[string]interface{}
		err = json.Unmarshal([]byte(decryptedVal), &secretMap)
		if err != nil {
			return nil, err
		}
		return secretMap, nil
	}

	// Decrypt the secret value and convert it back to a map
	if val, ok := secret["value"].(string); ok {
		decryptedVal, err := decryptValue(val)
		if err != nil {
			return nil, err
		}
		var secretMap map[string]interface{}
		err = json.Unmarshal([]byte(decryptedVal), &secretMap)
		if err != nil {
			return nil, err
		}
		return secretMap, nil
	}
	return nil, fmt.Errorf("secret value not found or not a string")
}

// Encryption key (should be stored securely)
var encryptionKey = []byte("mysecretencryptionkey32charslong") // Must be 16, 24, or 32 bytes long

// encryptValue encrypts a string value using AES.
func encryptValue(value string) (string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	ciphertext := gcm.Seal(nonce, nonce, []byte(value), nil)
	return hex.EncodeToString(ciphertext), nil
}

// decryptValue decrypts a string value using AES.
func decryptValue(encryptedValue string) (string, error) {
	ciphertext, err := hex.DecodeString(encryptedValue)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func main() {
	var store SecretStore
	var input int
	var err error

	for {
		fmt.Println("\nSelect the storage method:")
		fmt.Println("1. HashiCorp Vault")
		fmt.Println("2. In-Memory Store")
		fmt.Println("3. Exit")
		fmt.Print("Enter a number: ")
		_, err = fmt.Scan(&input)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		if input == 1 {
			store, err = NewVaultSecretStore("http://vault:8200", "dev-only-token") // For a Docker container
			// store, err = NewVaultSecretStore("http://127.0.0.1:8200", "dev-only-token") // For Windows localhost
		} else if input == 2 {
			store = NewInMemorySecretStore()
		} else {
			return
		}

		if err != nil {
			log.Fatalf("unable to initialize secret store: %v", err)
		}
	L:
		for {
			fmt.Println("\nMenu:")
			fmt.Println("1. Write a secret")
			fmt.Println("2. Read a secret")
			fmt.Println("3. Back")
			fmt.Print("Enter your choice: ")

			var choice int
			_, err := fmt.Scan(&choice)
			if err != nil {
				fmt.Println("Error:", err)
				continue
			}

			switch choice {
			case 1:
				var key, value, my_secret string
				fmt.Print("Enter secret: ")
				_, err := fmt.Scan(&my_secret)
				if err != nil {
					fmt.Println("Error:", err)
					continue
				}
				fmt.Print("Enter key: ")
				_, err = fmt.Scan(&key)
				if err != nil {
					fmt.Println("Error:", err)
					continue
				}
				fmt.Print("Enter value: ")
				_, err = fmt.Scan(&value)
				if err != nil {
					fmt.Println("Error:", err)
					continue
				}

				// Encrypt the value
				encryptedValue, err := encryptValue(value)
				if err != nil {
					fmt.Println("Error encrypting value:", err)
					continue
				}

				// Check if the secret already exists
				existingSecret, _ := store.Get(context.Background(), my_secret)
				// if err != nil && !apiErrNotFound(err) {
				// 	fmt.Println("Error checking secret existence:", err)
				// 	continue
				// }

				secretData := map[string]interface{}{
					key: encryptedValue,
				}

				if existingSecret != nil {
					// Patch the existing secret
					for k, v := range secretData {
						existingSecret[k] = v
					}
					err = store.Put(context.Background(), my_secret, existingSecret)
				} else {
					// Write a new secret
					err = store.Put(context.Background(), my_secret, secretData)
				}

				if err != nil {
					fmt.Println("Error writing secret:", err)
				} else {
					fmt.Println("Secret written successfully.")
				}

			case 2:
				var key, my_secret string
				fmt.Print("Enter secret: ")
				_, err := fmt.Scan(&my_secret)
				if err != nil {
					fmt.Println("Error:", err)
					continue
				}
				fmt.Print("Enter key: ")
				_, err = fmt.Scan(&key)
				if err != nil {
					fmt.Println("Error:", err)
					continue
				}
				secret, err := store.Get(context.Background(), my_secret)
				if err != nil {
					fmt.Println("Error reading secret:", err)
				} else {
					value, ok := secret[key].(string)
					if !ok {
						fmt.Println("Error: invalid secret value type")
					} else {
						value, err = decryptValue(value)
						if err != nil {
							fmt.Println("Error decrypting value:", err)
						} else {
							fmt.Printf("Key: %s, Value: %s\n", key, value)
						}
					}
				}

			case 3:
				break L
			default:
				fmt.Println("Invalid choice")
			}
		}
	}
}
