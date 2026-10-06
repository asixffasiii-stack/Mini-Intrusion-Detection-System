# Mini Intrusion Detection System (Python)

A beginner-friendly, defensive IDS that analyzes a security log and detects
possible brute-force activity based on repeated failed login attempts.

## Files

- `ids.py` - Main Python program
- `index.html` - Browser-based IDS, hosted as a static Vercel site
- `security.log` - Sample security events
- `alerts.log` - Created automatically when alerts are generated

## Requirements

- Python 3.x
- No external packages required

## Run

### Python command-line version

Open a terminal in this folder and run:

```bash
python ids.py
```

### Browser version

Open `index.html` in a browser, paste log entries or select a `.log`/`.txt`
file, and choose **Analyze log**. The browser version analyzes the log locally;
it does not upload the selected file. On Vercel, connect this repository and
deploy from the project root with no build command and no output directory.

## Detection rule

An IP address is flagged when it has 5 or more `FAILED_LOGIN` events.

## Example

The sample `security.log` contains five failed login attempts from
`192.168.1.20`, so the program reports a possible brute-force attack.

This project is intended for defensive learning and authorized lab/testing
environments.
