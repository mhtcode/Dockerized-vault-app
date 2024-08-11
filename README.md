# 🗄️ Dockerized Vault App

This is a Dockerized application for managing secrets using two different storage methods: HashiCorp Vault and an in-memory store. The application provides a simple interface to write and read secrets, ensuring secure and efficient secret management.

> [🚨Notice] 
> - **Two Running Methods**:
>  - **Running on a local machine.**
>  - **Running with Docker.**

**Comment or uncomment based on your running method:**
 ``` go
store, err = NewVaultSecretStore("http://vault:8200", "dev-only-token") // For a Docker container
// store, err = NewVaultSecretStore("http://127.0.0.1:8200", "dev-only-token") // For localhost
```


## ✨Features

- **Two Storage Methods**:
  - **HashiCorp Vault**: Securely store and manage secrets using HashiCorp Vault.
  - **In-Memory Store**: Store secrets in memory for quick and easy access during development or testing.
- 🔒**Encryption**: Encrypts secret values before storing them.
- 🔄 **Flexible Interface**: Easily switch between storage methods through a menu interface.
- 🐳**Dockerized**: Easily deploy the application using Docker.

## 📋Requirements

- Docker
- Go (for local development)
- HashiCorp Vault (for Vault storage method)

## 🚀Getting Started

### 1. Clone the Repository
```sh
git clone https://github.com/mhtcode/Dockerized-vault-app.git
cd dockerized-vault-app
```

### 2. Using docker-compose
```sh
docker-compose up --build
```

### 3. Interacting with running container
```sh
docker exec -it my-vault-app sh
```
### 4. Running ./main
```sh
./main
```


## EXAMPLE:
```plaintext
Select the storage method:
1. HashiCorp Vault
2. In-Memory Store
3. Exit
Enter a number: 1

Menu:
1. Write a secret
2. Read a secret
3. Back
Enter your choice: 1
Enter secret: names
Enter key: name
Enter value: masih
Secret written successfully.
```
