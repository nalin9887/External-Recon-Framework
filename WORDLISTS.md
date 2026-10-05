# Wordlist references

The framework defaults to the **SecLists raft-medium-words** list and offers small/medium/large at runtime.

## Kali / Debian package layout

- Small: `/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt`
- Medium: `/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt`
- Large: `/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt`

Install on Kali/Debian where the package is available:

```bash
sudo apt update && sudo apt install -y seclists
```

## User-local fallback

If the package is unavailable, the bootstrapper can use a user-local clone at:

```text
~/.local/share/SecLists/
```

Manual install:

```bash
git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/.local/share/SecLists
```

You can change all candidate paths in `config.json` without editing Python code.
