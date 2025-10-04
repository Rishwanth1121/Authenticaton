package main

import (
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	password := "temp123"

	// Generate hash
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Password: %s\n", password)
	fmt.Printf("Hash: %s\n", string(hash))

	// Verify the hash works
	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
	if err != nil {
		fmt.Println("❌ Hash verification failed")
	} else {
		fmt.Println("✅ Hash verification successful")
	}
}
