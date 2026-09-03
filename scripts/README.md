# Scripts

Reusable tools written to close gaps identified during assessments,
rather than doing the work by hand each time.

## xor_key_recovery.py

Recovers a repeating-key XOR key from ciphertext using a known-plaintext
crib. Useful when you've pulled an encrypted blob out of a binary
(config, string table, resource) and know or can guess a fragment of
the plaintext.

```
python3 xor_key_recovery.py --file blob.bin --crib "known_plaintext"
python3 xor_key_recovery.py --file blob.bin --crib "known_plaintext" --key-length 16
python3 xor_key_recovery.py --file blob.bin --decrypt-with 6b337921 --crib x
```

Tested against a synthetic sample; recovers the correct key at offset 0
and cleanly decrypts the full blob.
