# Lab 02 - JWT Signature and Claims Validation

**Transparency note:** I performed the lab myself, including the app registration, running the authentication flow, collecting the results, debugging issues and running the experiments. AI assistance from ChatGPT and Claude was used extensively for guidance, code generation, refactoring and reviewing the implementation. I worked through the code and concepts during the process, and the observations and experiment results documented below come from my own lab runs.

---

## Objective

The goal of this lab was to understand how an application should validate an ID token received from an OpenID Connect authentication flow.

In the previous lab I completed the OAuth 2.0 Authorization Code flow with PKCE and obtained an ID token and access token.

In this lab I wanted to understand what happens after the token is received.

The main questions I wanted to answer were:

- How does an application verify that a JWT was actually signed by the identity provider?
- How does `kid` help locate the correct signing key?
- How are RSA public key values obtained from JWKS?
- What exactly is being signed in a JWT?
- Why is a valid signature alone not enough?
- Which claims must also be validated?
- What happens when different parts of the token are modified?
- Why should the token never be allowed to decide where trusted signing keys come from?

---

# 1. Environment

- Python
- Microsoft Entra ID / Microsoft identity platform
- Personal Microsoft account
- OAuth 2.0 Authorization Code flow with PKCE
- OpenID Connect
- RS256 signed ID token
- Python `cryptography` library

The authentication flow used:

```text
Authorization endpoint
        ↓
Authorization Code
        ↓
Token endpoint
        ↓
ID Token
```

The ID token is then passed through the validation logic created in this lab.

---

# 2. Token Acquisition

I reused the Authorization Code + PKCE flow from the previous lab and later refactored it into smaller functions.

The script performs the following steps:

```text
Generate code_verifier
        ↓
Generate code_challenge
        ↓
Generate state
        ↓
Generate nonce
        ↓
Open authorization URL
        ↓
Receive authorization code on localhost
        ↓
Validate state
        ↓
Redeem authorization code
        ↓
Receive tokens
```

The nonce generated during the authorization request is stored locally so that it can later be compared against the nonce present in the ID token.

The token response itself is also stored locally for the validation exercises.

Both files are excluded from Git using `.gitignore`.

---

# 3. JWT Structure

A JWT consists of three Base64URL encoded parts:

```text
HEADER.PAYLOAD.SIGNATURE
```

The header contains information such as:

```json
{
  "alg": "RS256",
  "kid": "..."
}
```

The payload contains claims such as:

```text
iss
aud
exp
nbf
iat
nonce
sub
```

The signature protects the signed header and payload against modification.

---

# 4. Signing Input

The JWT signature is calculated over:

```text
Base64URL(header) + "." + Base64URL(payload)
```

This is referred to as the `signing_input`.

In Python:

```python
signing_input = f"{header}.{payload}".encode("ascii")
```

Any change to either the encoded header or encoded payload changes the signing input.

This means that even changing a single claim in the payload causes the existing signature to no longer verify.

---

# 5. OIDC Discovery and Trust

One of the more important things I learned in this lab was that the token itself should never determine where trust comes from.

An unsafe design would be:

```text
Read iss from token
        ↓
Build discovery URL from iss
        ↓
Download metadata
        ↓
Download JWKS
        ↓
Trust those keys
```

This allows an attacker-controlled token to potentially influence where the validator retrieves signing keys from.

The correct trust flow is:

```text
Application configured authority
        ↓
Trusted OIDC discovery document
        ↓
Expected issuer
        ↓
Trusted JWKS URI
        ↓
Trusted signing keys
```

The issuer inside the token is then compared against the expected issuer obtained from the trusted discovery document.

The token does not get to decide which identity provider should be trusted.

---

# 6. JWKS and kid

The JWT header contains a `kid` value.

The `kid` is a key identifier.

The identity provider publishes public signing keys through the JWKS endpoint. There can be multiple keys because identity providers may rotate their signing keys.

The validator performs:

```text
JWT header kid
        ↓
Search trusted JWKS
        ↓
Find matching key
        ↓
Use that public key
        ↓
Verify signature
```

The `kid` itself is not a trusted key.

It is only used as a selector to find a matching key inside the already trusted JWKS.

If no matching key exists, validation fails.

---

# 7. Building the RSA Public Key

The selected JWKS key contains values including:

```text
n - RSA modulus
e - RSA public exponent
```

These values are Base64URL encoded.

The lab decodes them and converts them into integers:

```python
exponent = int.from_bytes(exponent_bytes, byteorder="big")
modulus = int.from_bytes(modulus_bytes, byteorder="big")
```

The public key can then be reconstructed using:

```python
rsa.RSAPublicNumbers(exponent, modulus)
```

and converted into a usable RSA public key.

---

# 8. RS256 Signature Verification

The algorithm used by the ID token in this lab was `RS256`.

RS256 uses:

```text
RSA
+
SHA-256
+
PKCS#1 v1.5 padding
```

The signature verification using the `cryptography` library is performed using:

```python
public_key.verify(
    signature_bytes,
    signing_input,
    padding.PKCS1v15(),
    hashes.SHA256(),
)
```

If verification succeeds, the signed contents have not been modified and the signature was produced using the private key corresponding to the trusted public key.

However, this still does not mean that the token should automatically be trusted.

The claims must also be validated.

---

# 9. Manual RSA Verification

I also manually explored the RSA verification process to better understand what the cryptography library is doing internally.

The JWT signature was converted from bytes into an integer.

Then the RSA public operation was performed:

```python
recovered_int = pow(signature_int, exponent, modulus)
```

The result was converted back into bytes.

The recovered structure contained PKCS#1 v1.5 padding and the SHA-256 digest information.

The SHA-256 hash of the JWT signing input was calculated separately and compared with the digest recovered from the signature.

The values matched.

This helped me understand that the signature verification process involves recovering the encoded digest using the RSA public key and comparing it against a digest independently calculated from the received signing input.

The current manual implementation is intentionally basic and does not fully validate the complete PKCS#1 encoded structure.

---

# 10. Claims Validation

After signature verification, I added validation for the following claims.

## `iss` - Issuer

The token issuer must match the expected issuer obtained from trusted OIDC discovery.

```text
token iss == trusted expected issuer
```

---

## `aud` - Audience

The audience tells the application who the token was intended for.

For the ID token in this lab, the audience should match the application's client ID.

The validator handles both:

```text
aud as string
aud as list
```

---

## `exp` - Expiry

The application rejects the token once it has expired.

A small amount of clock skew is allowed to account for minor time differences between systems.

---

## `nbf` - Not Before

The token must not be accepted before its `nbf` timestamp.

Clock skew is also considered here.

---

## `iat` - Issued At

The `iat` value should not be significantly in the future.

A token claiming to have been issued beyond the allowed clock-skew window is rejected.

---

## `nonce`

The nonce inside the ID token is compared against the nonce stored when the authorization flow was started.

This binds the ID token to the original authorization request initiated by the application.

The comparison is performed using:

```python
secrets.compare_digest()
```

---

# 11. Validation Order

The final validator performs validation in this order:

```text
Incoming JWT
    ↓
Verify signature
    ↓
Parse payload
    ↓
Validate issuer
    ↓
Validate audience
    ↓
Validate exp
    ↓
Validate nbf
    ↓
Validate iat
    ↓
Validate nonce
    ↓
Token accepted
```

The final end-to-end validation returned:

```text
Token valid?: True
```

for the genuine ID token.

---

# 12. Break-It Experiments

I deliberately modified different parts of the token and validation inputs to understand how each protection works.

## Experiment 1: Payload tamper

Changing the payload while keeping the original signature causes signature verification to fail.

Result:

```text
Original token valid: True
Tampered token valid: False
```

---

## Experiment 2: Wrong audience

Changing the audience claim in the payload while keeping everything else the same causes audience verification to fail.

Result:

```text
Original audience valid: True
Modified audience valid: False
```

---

## Experiment 3: Wrong issuer

Changing the issuer changes the payload and makes the token invalid.

More importantly, the expected issuer is based on the trusted configured authority and is not decided by what is present in the token.

Result:

```text
Original issuer valid: True
Modified issuer valid: False
```

---

## Experiment 4: Tamper kid

The `kid` in the token should only be used to select a matching key from the trusted JWKS.

If no matching key exists in the trusted JWKS, the token is rejected.

Result:

```text
Original token valid: True
Tampered kid valid: False
```

---

## Experiment 5: Attacker-controlled JWKS

An incoming token must not control the discovery URL or JWKS source.

Discovery must begin from the application-configured trusted authority.

The token's `iss` is then compared against the issuer obtained from that trusted discovery document.

In the experiment, changing:

```text
iss = https://evil.example
```

showed that a design which derives discovery directly from the token would attempt to access:

```text
https://evil.example/.well-known/openid-configuration
```

The corrected validator does not do this.

The attacker-controlled issuer is rejected against the trusted issuer.

---

## Experiment 6: Expired token

Changing the `exp` claim to a timestamp in the past causes expiry validation to fail.

Clock skew can provide a small tolerance, but once the expiry is outside that window the token is rejected.

Result:

```text
Original expiry valid: True
Expired token valid: False
```

---

## Experiment 7: Future nbf

Changing the `nbf` claim to a timestamp sufficiently in the future causes the token to be rejected.

The token should only be accepted once the current time is within the allowed `nbf` window after considering clock skew.

Result:

```text
Original nbf valid: True
Future nbf valid: False
```

---

## Experiment 8: Unexpected algorithm

Changing the `alg` value from `RS256` to `none` or `HS256` causes validation to fail.

The application should enforce the expected signing algorithm and should not allow the token header to decide which algorithm will be trusted.

Result:

```text
Original algorithm: RS256
Original token valid: True

alg=none token valid: False
alg=HS256 token valid: False
```

---

## Experiment 9: Wrong nonce

Using a nonce different from the one stored when the authorization request was initiated causes nonce validation to fail.

The nonce is used to bind the ID token to the original authorization request started by the application.

Result:

```text
Original nonce valid: True
Wrong nonce valid: False
```

---

# 13. What the Experiments Demonstrated

The experiments covered different validation failures:

```text
Payload tampering
    → Integrity failure

Wrong issuer
    → Trust validation failure

Wrong audience
    → Token intended for another recipient

Unknown kid
    → Trusted signing key cannot be found

Attacker-controlled issuer
    → Trust-source problem

Expired token
    → Token lifetime failure

Future nbf
    → Token used before valid time

Unexpected alg
    → Algorithm confusion / unsafe algorithm selection

Wrong nonce
    → Authentication transaction mismatch
```

---

# 14. Signature Validation Is Not Token Validation

A major lesson from this lab was that successful signature verification does not automatically make a token valid.

A token can have a valid signature and still need to be rejected.

For example:

```text
Valid signature + wrong audience
    → Reject

Valid signature + expired token
    → Reject

Valid signature + wrong issuer
    → Reject

Valid signature + wrong nonce
    → Reject
```

Therefore:

```text
Valid signature
        ≠
Valid token
```

Token validation requires both cryptographic validation and claims validation.

---

# 15. Stolen Valid Tokens

Another important limitation became clear during this lab.

A valid stolen bearer token can still be a valid token.

If the token:

- has a valid signature
- has not expired
- contains the correct audience
- contains the correct issuer
- passes the normal validation checks

then the application may still accept it.

The validator can determine whether the token itself is valid.

It may not be able to determine whether the person presenting the bearer token is the legitimate holder.

This is why token theft and session theft require additional protections beyond normal JWT signature and claims validation.

---

# 16. Things I Initially Got Wrong

A few mistakes during the lab helped reinforce the concepts.

## Using the token issuer to find discovery metadata

The initial implementation used the issuer from the incoming token to determine the discovery endpoint.

This created a trust problem because an attacker-controlled token could influence where trust information was fetched from.

This was corrected by starting discovery from the configured trusted authority.

---

## Passing the wrong object into functions

At different points I passed:

```text
token response dictionary
```

where a function expected:

```text
JWT string
```

or passed:

```text
aud claim value
```

where the validator expected:

```text
complete payload dictionary
```

This helped me understand function inputs and what a function expects more clearly.

---

## `exp` and `nbf` confusion

During time validation I accidentally referenced the wrong claim when checking `nbf`.

Printing the timestamps in human-readable form helped identify the mistake.

---

## Relative file paths

Files such as:

```text
token_response.json
session.json
```

were written relative to the current working directory.

This meant running the script from different directories could create the files in different locations.

This can later be improved using `pathlib` and paths relative to the script location.

---

# 17. Things I Still Want to Improve

The lab works for the scenarios I tested, but there are still a few areas I may improve later.

- Add automated tests for the validation functions
- Improve file path handling
- Improve error handling and logging
- Handle JWKS key refresh more cleanly when a `kid` is not found
- Improve the manual PKCS#1 v1.5 verification if I revisit the cryptography part
- Avoid storing token responses to disk outside of a lab environment

---

# 18. Mental Model

My current mental model for ID token validation is:

```text
Do I trust this identity provider?
        ↓
Use configured authority
        ↓
Get trusted discovery metadata
        ↓
Get trusted signing keys
        ↓
Does token kid match one of those keys?
        ↓
Verify cryptographic signature
        ↓
Does issuer match?
        ↓
Was token issued for my application?
        ↓
Is token valid at the current time?
        ↓
Does nonce match my authorization transaction?
        ↓
Accept token
```

The important rule is:

> Trust must start from application configuration, not from information supplied by the incoming token.

---

# What I Learned

## 1. JWT structure and signing

JWT is of the form:

```text
header.payload.signature
```

The signature is calculated over the full Base64URL encoded `header`, `"."`, and `payload`, referred to as the `signing_input`.

Changing any part of either the `header` or the `payload` changes the signing input and therefore changes the SHA-256 hash calculated over it. The existing `signature` will no longer verify against this modified hash, which results in the token getting rejected.

---

## 2. Working of RS256 Validation

The algorithm observed during the learning is RS256, which means RSA signature with SHA-256 hash and PKCS#1 v1.5 padding.

The `alg` value in the token header tells the validator which algorithm the token claims was used. This value should not be blindly trusted and must be compared against the algorithm allowed by the application, which in this lab was `RS256`.

The header also provides a `kid`, which is used to select the matching key from the trusted JWKS. This key contains `n` (modulus) and `e` (public exponent), which can be decoded and used to construct the public key used to verify the signature.

As part of the signature validation, I also attempted to manually understand the RSA verification process. I reconstructed the `signing_input` and decoded the `signature`, `modulus`, and `public exponent`. I then used the Python function:

```python
pow(signature_int, exponent, modulus)
```

to recover the PKCS#1 encoded structure.

I also calculated the SHA-256 hash of the `signing_input` and compared it against the digest recovered from the signature.

I also read about the structure of PKCS#1 v1.5 and understood that the SHA-256 digest is wrapped in a `DigestInfo` structure and padded to the RSA key size. In this case, with a 2048-bit RSA key, the final encoded structure is 256 bytes.

---

## 3. Trust models

The token must not decide what identity provider is trusted.

The trusted authority, expected algorithms, and trusted key source should come from the trust settings of the application.

In my learning environment, the configured authority is:

```text
https://login.microsoftonline.com/consumers
```

This was used to fetch the trusted OIDC discovery document, which provides the expected issuer and the JWKS URI.

The `iss` claim in the payload is then compared against this trusted issuer. The `kid` from the token is only used to select a matching key from the trusted JWKS.

If the issuer does not match or the `kid` cannot be found in the trusted JWKS, the token should be rejected.

I also learned that signature validation is not the same as token validation.

Signature validation proves that the signed contents have not been altered and that the signature was created using the private key corresponding to the trusted public key. However, the application should still verify the relevant claims in the payload.

It is possible that the token was issued by an unexpected issuer, was meant for another audience, has expired, is not valid yet, or has the wrong nonce.

Another important distinction, and a limitation of bearer tokens, is that a valid stolen bearer token can still be a valid token.

If the token has not expired and all the normal validation checks pass, the application may not be able to determine whether the current presenter is the legitimate holder.

There are ways to reduce this risk, such as sender-constrained tokens, which I have not explored yet.

---

## 4. Claims

I came across the following important claims in the payload:

- `iss` tells you who issued the token.
- `aud` tells you who the token was intended for.
- `exp` tells you when it expires.
- `nbf` tells you when it becomes valid.
- `iat` tells you when it was issued.

Further, the `nonce` value binds the ID token to the original authorization request initiated by the application.

---

## 5. Some software development concepts learned

- Worked with Python dictionaries and understood the difference between accessing a value using `dict["key"]` and `dict.get("key")`.
- Learned some basics of encoding and decoding, especially Base64URL, and working with JSON data.
- Did some code refactoring with the help of ChatGPT and learned how breaking larger scripts into smaller functions makes the code easier to understand and reuse.
- Learned when to use functions, how to define and structure them, how parameters and return values work, and how to add type hints for both.
- Learned the purpose of `if __name__ == "__main__":` and why it is useful when a Python file can either be run directly or imported as a module.
- Learned how to read from and write to files using Python.
- Got more familiar with the difference between strings and bytes, especially while working with hashing, Base64URL encoding, and HTTP responses.
- Worked with basic exception handling using `try`, `except`, and `finally`.
- Learned some basic Git usage including `.gitignore`, `git add`, `git status`, `git diff`, `git commit`, and `git push`, along with concepts such as tracked, untracked, staged, and unstaged files.

---

# Next Steps

The next part of the learning journey is to go beyond normal token validation and understand attacks against OAuth, OIDC and authenticated sessions.

Topics I want to explore next include:

- Authorization code interception
- Redirect URI attacks
- State misuse
- Nonce misuse
- Consent phishing
- Token theft
- Access token replay
- Refresh token theft
- Browser session theft
- Attacker-in-the-middle attacks
- Sender-constrained tokens
- Token and session protection