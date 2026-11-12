# IRONKEY — Encrypted Password Management System

> **"Your Credentials. Your Control."**

IRONKEY is a standalone, security-first Java desktop password management system engineered with zero-knowledge cryptographic principles. It provides an isolated, local-first client architecture where all sensitive credentials are encrypted using **AES-256-GCM** before being persisted to a MySQL database. Master passwords are never transmitted in plaintext or stored in raw format, and authentication is decoupled from vault encryption key derivation.

---

## Architecture & Security Highlights

- **Zero-Knowledge Architecture:** Decryption happens exclusively in-memory on the client desktop. Decryption keys are derived on the fly from the user's master password and are never stored on disk or in the database.
- **Cryptographic Separation:** Authentication password hashing (`PBKDF2WithHmacSHA256`) and AES-256 vault encryption key derivation use independent, distinct cryptographically secure salts. Even an attacker with complete read access to the MySQL database cannot decrypt vault credentials without the master password.
- **AES-256-GCM Authenticated Encryption:** Every credential record is encrypted using a unique, 12-byte initialization vector (`nonce`) and validated with a 128-bit Galois/Counter Mode authentication tag to protect against unauthorized tampering.
- **Fresh Nonces per Field & Operation:** Distinct, independent nonces are generated for username, password, and notes, completely eliminating GCM nonce-reuse vulnerabilities.
- **Constant-Time Verification:** Password verification relies on `MessageDigest.isEqual` to prevent timing attack side channels.
- **Strict Data Isolation:** Database tables enforce foreign key relationships and index-level isolation (`user_id` scope) on all DAO queries.
- **Secure Clipboard Scrubbing:** Copied passwords reside in the system clipboard for a maximum of 30 seconds before being automatically purged by a background daemon.
- **Ephemeral In-Memory Handling:** Sensitive plaintext credentials are not retained in long-lived UI components and are masked by default (`••••••••••••`).

---

## Technology Stack

| Component | Technology | Description |
|---|---|---|
| **Language** | Java 17+ (LTS) | Modern Java core standard library |
| **GUI Framework** | Java Swing + Java2D | Hardware-accelerated desktop UI with custom dark cybersecurity aesthetic |
| **Database** | MySQL 8.0+ | Relational storage for user accounts and encrypted payloads |
| **Database Connectivity** | JDBC (`mysql-connector-j`) | Type-safe SQL execution via `PreparedStatement` |
| **Build Tool** | Apache Maven 3.9+ | Standard dependency resolution and build automation |
| **Password Hashing** | `PBKDF2WithHmacSHA256` | 310,000 iterations (OWASP recommendation) |
| **Credential Encryption** | `AES-256-GCM` | 256-bit symmetric key with 12-byte unique nonces and 128-bit authentication tags |
| **Testing** | JUnit Jupiter 5.10+ | Comprehensive test suite (85 tests across 17 classes) |

---

## Project Structure

```
d:/securevault java/
├── pom.xml                               # Maven project configuration
├── application.properties.example        # Template for local environment overrides
├── .gitignore                            # VCS exclusions for secrets, target, and IDE files
├── README.md                             # Comprehensive technical documentation
├── src/
│   ├── main/
│   │   ├── java/com/ironkey/
│   │   │   ├── Main.java                 # Desktop bootstrap & Look & Feel initialization
│   │   │   ├── config/
│   │   │   │   └── DatabaseConfig.java   # JDBC connection manager with diagnostics
│   │   │   ├── model/
│   │   │   │   ├── User.java             # User entity with auth salts
│   │   │   │   ├── VaultEntry.java       # Encrypted credential container
│   │   │   │   ├── VaultAuditReport.java # Security audit structured findings
│   │   │   │   ├── Category.java         # Credential categories
│   │   │   │   └── SecurityLog.java      # Security audit log model
│   │   │   ├── dao/
│   │   │   │   ├── UserDAO.java          # Prepared-statement user persistence
│   │   │   │   ├── VaultEntryDAO.java    # Multi-tenant isolated vault persistence
│   │   │   │   ├── CategoryDAO.java      # Category management DAO
│   │   │   │   └── SecurityLogDAO.java   # Security audit logger
│   │   │   ├── service/
│   │   │   │   ├── AuthenticationService.java # Registration and session management
│   │   │   │   ├── VaultService.java          # Encryption, CRUD, and credential lifecycle
│   │   │   │   ├── SecurityAuditService.java  # In-memory password health & reuse audit
│   │   │   │   └── SecurityService.java       # Security scoring and audit logging
│   │   │   ├── security/
│   │   │   │   ├── EncryptionManager.java          # AES-256-GCM engine
│   │   │   │   ├── PasswordHasher.java             # PBKDF2 authentication hasher
│   │   │   │   ├── KeyDerivationService.java       # Dedicated AES key derivation
│   │   │   │   ├── PasswordGenerator.java          # Configurable password entropy generator
│   │   │   │   └── PasswordStrengthAnalyzer.java   # Password strength & entropy engine
│   │   │   ├── ui/
│   │   │   │   ├── LoginFrame.java              # Vault unlock & authentication screen
│   │   │   │   ├── RegisterFrame.java           # Vault initialization screen
│   │   │   │   ├── DashboardFrame.java          # Main management dashboard
│   │   │   │   ├── CredentialDialog.java        # Modal Add/Edit dialog with generator
│   │   │   │   ├── PasswordGeneratorDialog.java # Standalone/embedded generator dialog
│   │   │   │   └── components/
│   │   │   │       ├── Sidebar.java             # Responsive navigation sidebar
│   │   │   │       └── CredentialCard.java      # Credential card with reveal & clipboard
│   │   │   └── util/
│   │   │       ├── ClipboardManager.java # 30s auto-clearing clipboard scrubber
│   │   │       ├── InputValidator.java   # Email, username, password validation
│   │   │       ├── SessionManager.java   # In-memory session key manager
│   │   │       └── UITheme.java          # Cyber dark design system & custom components
│   │   └── resources/
│   │       ├── application.properties    # Default application properties
│   │       └── schema.sql                # Complete MySQL DDL schema
│   └── test/
│       └── java/com/ironkey/
│           ├── PasswordStrengthAnalyzerTest.java  # Password strength, patterns & entropy tests
│           ├── PasswordReuseDetectionTest.java    # Duplicate detection & grouping tests
│           ├── PasswordHealthScoreTest.java       # Health score formula & boundary tests
│           ├── SecurityAuditServiceTest.java      # End-to-end security audit tests
│           ├── AuthenticationServiceTest.java     # Full unit test suite for auth & session
│           ├── AuthenticationIntegrationTest.java # Live MySQL auth integration test
│           ├── CredentialManagementTest.java      # Full Phase 4 CRUD & encryption test suite
│           ├── VaultIntegrationTest.java          # Live MySQL vault CRUD integration test
│           ├── EncryptionManagerTest.java         # AES-GCM encryption & tamper tests
│           ├── PasswordHasherTest.java            # PBKDF2 hash & separation tests
│           ├── InputValidatorTest.java            # Input validation test suite
│           ├── DatabaseConfigTest.java            # JDBC configuration & health test
│           ├── TransactionRollbackTest.java       # Atomic transaction rollback tests
│           ├── UserIsolationTest.java             # Multi-tenant isolation verification
│           ├── VaultSecurityAuditTest.java        # Tamper, nonce, & wrong-key audit
│           └── UIFrameInitializationTest.java     # Swing component construction tests
```

---

## Prerequisites

1. **Java Development Kit (JDK):** Version 17 or higher (LTS recommended).
2. **Apache Maven:** Version 3.8.0 or higher.
3. **MySQL Server:** Version 8.0 or higher.

To verify your environment:
```powershell
java -version
mvn -version
```

---

## MySQL Installation & Database Setup

### 1. Install MySQL
If MySQL is not yet installed:
- Download and install MySQL Community Server from [dev.mysql.com](https://dev.mysql.com/downloads/mysql/).
- During setup, configure MySQL to run on the standard port `3306` and set a root password.

### 2. Initialize the Database Schema
Launch the MySQL command line client or MySQL Workbench and run:

```bash
mysql -u root -p < src/main/resources/schema.sql
```

This creates:
- Database: `ironkey_db`
- Tables: `users`, `categories`, `vault_entries`, `security_logs`
- Default categories: *Logins*, *Financial*, *Secure Notes*, *Identities*, *Servers & SSH*

---

## JDBC Configuration

IRONKEY resolves configuration via a three-tier hierarchy:

1. **Environment Variables** (Highest precedence):
   - `IRONKEY_DB_HOST` (e.g., `localhost`)
   - `IRONKEY_DB_PORT` (e.g., `3306`)
   - `IRONKEY_DB_NAME` (e.g., `ironkey_db`)
   - `IRONKEY_DB_USER` (e.g., `root`)
   - `IRONKEY_DB_PASS` (e.g., `your_secure_password`)

2. **Local Configuration File:**
   Copy `application.properties.example` to `config/application-local.properties` (excluded by `.gitignore`):
   ```properties
   db.host=localhost
   db.port=3306
   db.name=ironkey_db
   db.user=root
   db.password=your_secret_password
   ```

3. **Classpath Default:**
   Fallback values located in `src/main/resources/application.properties`.

---

## Maven Build, Test & Packaging

To compile the project:
```powershell
mvn clean compile
```

To run the automated test suite (85 unit and integration tests across 17 test suites):
```powershell
mvn test
```

To package the application into a standard JAR:
```powershell
mvn package
```

The compiled JARs are generated in `target/`:
- Standard JAR: `target/ironkey-vault-1.0.0-SNAPSHOT.jar`
- Standalone Executable Fat JAR: `target/ironkey-vault-1.0.0-SNAPSHOT-jar-with-dependencies.jar`
- Runtime Dependencies: `target/lib/mysql-connector-j-8.3.0.jar`

---

## Running the Application

### Option 1: Standalone Fat JAR (Recommended)
```powershell
java -jar target/ironkey-vault-1.0.0-SNAPSHOT-jar-with-dependencies.jar
```

### Option 2: Standard JAR with Lib Directory
```powershell
java -cp "target/ironkey-vault-1.0.0-SNAPSHOT.jar;target/lib/*" com.ironkey.Main
```

### Option 3: Headless Diagnostic Execution
```powershell
java -Djava.awt.headless=true -jar target/ironkey-vault-1.0.0-SNAPSHOT-jar-with-dependencies.jar
```

---

## Security Verification & Auditing Summary

- **Zero Plaintext Storage:** Passwords, usernames, and notes are encrypted with AES-256-GCM.
- **Cryptographic Tag Authentication:** GCM 128-bit authentication tags prevent unauthorized tampering or ciphertext modification.
- **Multi-Tenant User Isolation:** Users can never access, edit, or delete credentials owned by another account.
- **Ephemeral Secrets:** Master password character arrays and derived AES keys are purged from volatile memory upon session termination.
