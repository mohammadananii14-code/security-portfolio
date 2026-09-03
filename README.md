# Security Research & CTF Portfolio

Writeups, tooling, and notes from penetration testing practice and CTF work.

## Structure

| Folder | Contents |
|---|---|
| `mobile-android/` | Android application security assessments |
| `ctf-writeups/` | HackTheBox / CTF box writeups (retired boxes only) |
| `web-exploitation/` | Web application vulnerability research, methodology-focused |
| `linux-privesc/` | Linux privilege escalation writeups |
| `scripts/` | Reusable tools built during assessments |
| `templates/` | Writeup template used across this repo |

## Before publishing a writeup

- [ ] Confirm the box/lab is officially retired or disclosure is permitted
- [ ] Strip any real credentials, tokens, IPs, or client-identifying info
- [ ] Write web findings as methodology/concept, not a literal walkthrough,
      if the source platform's terms restrict publishing solutions
- [ ] Commit on a realistic, incremental cadence rather than one dump

## How each writeup is organized

Every finding folder follows the same shape:

```
<finding-name>/
├── README.md      # the writeup itself (from templates/WRITEUP_TEMPLATE.md)
├── evidence/       # screenshots, logs
└── scripts/        # any helper code specific to this target (optional)
```

## Contact

<!-- add your contact / LinkedIn / etc. -->
