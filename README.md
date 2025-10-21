# AWPM (Acid Weaver`s Password Manager)

⚠ **Development-time README — for internal use**

---

## 🔑 Summary
AWPM is a C-based credential manager supporting:
- Linux distro (developed on Arch)
- SQLite database for storage
- OpenSSL encryption (AES-256 + PBKDF2)
- Configurable options (INI config with `inih`)
- CLI, TUI

---

## 🛠 Build instructions
```bash
make install

---

## Development notes.
Internal mem.h library mainly to handle strings and bin data, accumulating low lvl memory managment functions
High lvl structures are user_t and cred_data_t should be processed only with related functions

