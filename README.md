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

## Development Roadmap & Status

IRONKEY is being developed incrementally across 7 distinct phases:

- [x] **Phase 1: Project Foundation, Maven, MySQL Schema, JDBC Configuration, and Swing UI** *(Completed)*
- [x] **Phase 2: User Registration and Authentication Workflows** *(Completed)*
- [x] **Phase 3: Vault Security Audit & Database Integration** *(Completed)*
- [x] **Phase 4: Complete Credential Management & Persistent Vault** *(Completed)*
- [x] **Phase 5: Password Health Analyzer & Security Audit Dashboard** *(Completed)*
- [ ] **Phase 6: Auto-Lock, Clipboard Protection, and Audit Logging**
- [ ] **Phase 7: End-to-End Testing, Hardening, and Production Packaging**

---

## Phase 5: Password Health Analyzer & Security Audit Dashboard

### 1. Password Strength Analyzer (`PasswordStrengthAnalyzer`)
- **Multi-Factor Evaluation:**
  - Length evaluation across progressive security thresholds ($< 8$, $8-11$, $12-15$, $16-19$, $\ge 20$).
  - Character class diversity across 4 sets: lowercase ($26$), uppercase ($26$), digits ($10$), symbols ($33$).
  - Dictionary blacklist check across top 200+ prevalent and predictable passwords.
  - Spatial keyboard walk detection (e.g. `qwerty`, `asdfgh`, `123456`).
  - Alphabetical & numeric sequential pattern detection (forward & backward: `abc`, `cba`, `123`, `321`).
  - Consecutive repeated character detection (`aaaa`, `1111`).
  - Character diversity ratio calculation ($\frac{\text{UniqueChars}}{\text{Length}}$).
- **Shannon / Keyspace Entropy Estimation:**
  $$E_{\text{base}} = L \cdot \log_2(R)$$
  Where $R$ is active keyspace pool size and $L$ is length. Penalty deduction ratios are applied for sequential patterns, repeated runs, and dictionary words to calculate adjusted entropy $E_{\text{adj}}$.
- **Deterministic Classification:**
  - `VERY_WEAK` (0 – 29 pts)
  - `WEAK` (30 – 49 pts)
  - `MODERATE` (50 – 69 pts)
  - `STRONG` (70 – 84 pts)
  - `VERY_STRONG` (85 – 100 pts)

### 2. Privacy-Preserving In-Memory Reuse Detection
- **Zero Plaintext Persistence:** Credentials are decrypted exclusively in volatile memory during audit evaluation.
- **Group Isolation:** Accounts sharing identical passwords are grouped, counting affected services without storing or logging plaintext secrets or creating persistent unsalted hashes.
- **Immediate Scrubbing:** In-memory comparison maps are scrubbed and cleared immediately upon audit completion.

### 3. Password Age Analysis
- Configurable threshold (default: 180 days).
- Uses `updated_at` and `created_at` timestamps from `vault_entries`.
- Transparently labeled as a password age hygiene indicator, not false proof of compromise.

### 4. Deterministic Vault Health Scoring Algorithm
The vault security score is calculated on a deterministic scale from 0 to 100:
$$\text{Score} = \max\Big(0, 100 - (\text{Penalty}_{vw} + \text{Penalty}_{w} + \text{Penalty}_{reuse} + \text{Penalty}_{outdated})\Big)$$
Where:
- $\text{Penalty}_{vw} = \min\Big(40, \big(\frac{N_{vw}}{N} \times 35\big) + (N_{vw} \times 5)\Big)$
- $\text{Penalty}_{w} = \min\Big(25, \frac{N_{w}}{N} \times 25\Big)$
- $\text{Penalty}_{reuse} = \min\Big(30, \big(\frac{N_{reused}}{N} \times 25\big) + (\text{Groups} \times 2)\Big)$
- $\text{Penalty}_{outdated} = \min\Big(15, \frac{N_{outdated}}{N} \times 15\Big)$

Empty vaults default to 100 with an "Empty Vault" rating and guidance to add credentials. Deductions are individually documented in the report with transparent explanations.

### 5. Security Audit Dashboard UI
- **Health Score Hero Badge:** Dynamic color-coded score (Emerald $\ge 90$, Bronze $70-89$, Amber $50-69$, Danger $< 50$).
- **4 Key Stat Cards:** Strong passwords, Weak passwords, Reused accounts, Outdated passwords.
- **Segmented Findings Views:**
  - **Weak Passwords Tab:** Lists affected credentials with specific weakness tags and direct **"⚡ Fix Password"** action opening `CredentialDialog`.
  - **Reused Passwords Tab:** Shows duplicate groups with affected accounts and **"✏️ Make Unique"** actions.
  - **Outdated Passwords Tab:** Displays age in days with **"✏️ Rotate"** actions.
  - **Recommendations & Deductions Tab:** Itemized breakdown of point deductions and security recommendations.

---

## Phase 4: Credential Management Implementation Details

### 1. Persistent Credential Operations (CRUD)
- **Add Credential (`CredentialDialog` & `VaultService.addEntry`):**
  - Accepts website name, login URL, username, password, category, and multiline notes.
  - Validates required inputs (non-empty site name, username, password).
  - Encrypts sensitive fields (`username`, `password`, `notes`) using client-side AES-256-GCM.
  - Each field receives an independent 12-byte random nonce from `SecureRandom`.
  - Persists record with timestamps to `vault_entries` table under active `user_id`.
- **View Credential (`CredentialCard`):**
  - Renders site glyph, site name, category badge, timestamp, URL, and username.
  - Password remains masked (`••••••••••••`) by default.
  - On-demand password reveal decrypts plaintext only in volatile memory when requested.
  - Password mask toggle re-hides the secret and clears plaintext from the UI.
- **Edit Credential (`CredentialDialog` in edit mode):**
  - Pre-populates decrypted fields in the dialog.
  - Re-encrypts modified attributes with fresh, independent nonces upon save.
  - Verifies ownership (`WHERE entry_id = ? AND user_id = ?`) in MySQL to prevent IDOR attacks.
- **Delete Credential (`CredentialCard.confirmAndDelete`):**
  - Requires explicit user confirmation via dialog.
  - Executes ownership-scoped SQL delete (`DELETE FROM vault_entries WHERE entry_id = ? AND user_id = ?`).
  - Logs security audit event (`CREDENTIAL_DELETED`).

### 2. Search and Category Filtering
- **Real-Time Client-Side Search:** Search field dynamically matches against website name, URL, or decrypted username in real time without leaking decrypted queries to SQL logs.
- **Category Filtering:** Quick category dropdown filter on the dashboard header ("All Categories", "Logins", "Financial", "Secure Notes", "Servers", "Social", "Work").
- **Dynamic Empty States:** Automatically switches between empty vault view, no-search-matches view, and populated credential card list.

### 3. Clipboard Management (`ClipboardManager`)
- **30-Second Password Auto-Scrubbing:** When copying a password, a background daemon (`IronKey-ClipboardScrubber`) schedules automatic clipboard clearing after 30 seconds.
- **Interim Change Protection:** If the user copies another string before the 30 seconds elapse, the clipboard is left untouched to prevent overwriting new user data.
- **Non-Expiring Username Copy:** Usernames and URLs are copied without auto-clear.

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
