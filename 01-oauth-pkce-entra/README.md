# OAuth 2.0 Authorization Code Flow with PKCE — Microsoft Entra

A hands-on lab implementing the OAuth 2.0 Authorization Code Flow with PKCE manually against Microsoft Entra, without MSAL or an SDK.

The lab was designed to understand the protocol at the request/response level and then deliberately break individual security controls to observe how Entra responds.

> **Transparency note:** I performed the lab myself, including app registration, running the commands, collecting the results, and conducting the security experiments. AI assistance was used for guidance and starter code. The observations below are from my own experiments.

---

## 1. Environment

- Microsoft Entra ID
- Personal Microsoft account
- Free Azure trial
- Entra app registration configured as a **Mobile and desktop application / public client**
- Redirect URI: `http://localhost`
- Python 3 (standard library only)
- PowerShell `curl.exe`
- jwt.ms
- Microsoft Graph `/me` endpoint

### Scopes requested

```text
openid offline_access User.Read
```

No production credentials, secrets, access tokens, or refresh tokens are included in this repository.

---

# 2. What is PKCE?

In the Authorization Code Flow, the authorization code travels through the browser and could potentially be intercepted.

For a public client, there is no client secret that can be used to authenticate the application during token redemption.

PKCE addresses this by introducing a one-time secret called the `code_verifier`.

The flow is:

```text
1. Client generates a random code_verifier

       code_verifier
             |
             | SHA-256
             v
       code_challenge


2. Client sends the code_challenge
   in the authorization request

       Browser
          |
          | code_challenge
          v
       Entra


3. Entra returns an authorization code

       Entra
          |
          | authorization code
          v
       Browser / Client


4. Client sends the authorization code
   together with the original code_verifier

       Client
          |
          | code + code_verifier
          v
       Entra Token Endpoint


5. Entra hashes the verifier and compares it
   with the original code_challenge.

       SHA256(code_verifier)
                ==
       stored code_challenge

                |
                v
             Tokens
```

## Why does the hash go first?

The authorization request travels through the browser, which is the channel PKCE is designed to protect.

If the original `code_verifier` were sent in the authorization request, an attacker who captured that request could obtain the secret required to redeem the authorization code.

Instead, only the `code_challenge` is sent.

The original verifier is retained by the client and sent later during the token exchange.

An attacker who obtains only the authorization code therefore does not have the verifier required to redeem it.

---

# 3. PKCE Implementation

The verifier was generated using Python's `secrets` module:

```python
import secrets
import hashlib
import base64

code_verifier = secrets.token_urlsafe(64)

digest = hashlib.sha256(
    code_verifier.encode("ascii")
).digest()

code_challenge = base64.urlsafe_b64encode(
    digest
).decode("ascii").rstrip("=")
```

Important implementation details:

- `secrets` is used instead of `random` because the verifier must be unpredictable.
- SHA-256 operates on the ASCII bytes of the verifier.
- `.digest()` is used rather than `.hexdigest()`.
- Base64 URL encoding is used.
- Base64 padding (`=`) is removed.
- A new verifier is generated for every authorization attempt.

---

# 4. `state`, `nonce`, and PKCE

These three values can look similar but perform different security functions.

| Mechanism | What it binds | Who validates it |
|---|---|---|
| `code_challenge` / `code_verifier` | Authorization request and token redemption | Entra |
| `state` | Authorization request and redirect response | Client application |
| `nonce` | Authorization request and ID token | Client application |

This distinction became particularly clear during the breaking tests.

---

# 5. Authorization Request

The authorization request contained:

```text
client_id
response_type=code
redirect_uri=http://localhost
scope=openid offline_access User.Read
state
code_challenge
code_challenge_method=S256
nonce
```

The authorization endpoint used was:

```text
https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize
```

After authentication, Entra redirected the browser to the registered redirect URI with an authorization code and `state`.

Because nothing was listening on `localhost`, the browser displayed a connection error. The authorization code and state were nevertheless visible in the browser address bar.

---

# 6. Token Exchange

The authorization code was redeemed against the token endpoint using PowerShell `curl.exe`.

The request contained:

```text
grant_type=authorization_code
client_id=<CLIENT_ID>
code=<CODE>
redirect_uri=http://localhost
code_verifier=<VERIFIER>
```

The token response contained:

- `access_token`
- `id_token`
- `refresh_token`
- `expires_in`

---

# 7. Token Analysis

## ID Token

The ID token was decoded using jwt.ms.

| Claim | Meaning | Observation |
|---|---|---|
| `aud` | Who the token is intended for | Matched the application's client ID |
| `iss` | Token issuer | Microsoft identity platform |
| `tid` | Tenant identifier | Personal Microsoft account tenant |
| `exp` | Expiration time | Approximately 24 hours after `iat` |
| `nonce` | Value associated with the authentication request | Present in the token |
| `sub` | Subject identifier | Pairwise identifier; differed from the Microsoft Graph user ID |
| `ver` | Token version | `2.0` |

### Observation

The `aud` claim in the ID token matched the application's client ID.

The `sub` claim was different from the user's Microsoft Graph `id`, demonstrating that the identifiers serve different purposes.

---

## Access Token

The access token could not be decoded using jwt.ms.

Rather than assuming that the token was invalid, I tested it against Microsoft Graph:

```http
GET https://graph.microsoft.com/v1.0/me
Authorization: Bearer <ACCESS_TOKEN>
```

The request successfully returned the user's profile.

### Observation

The access token was not a normal JWT that could be decoded by the client.

This reinforced an important distinction:

- **ID token** — intended for the client application to consume.
- **Access token** — intended for the resource/API.
- An access token should not be assumed to be a JWT or something the client should interpret.

I therefore did not observe the `scp` claim in this experiment.

---

# 8. Breaking the Flow

Each experiment used a fresh authentication attempt and changed one variable at a time.

| Experiment | Result | Error |
|---|---|---|
| Wrong verifier | Token redemption failed | `invalid_grant`, `AADSTS70000` |
| No verifier | Token redemption failed | `invalid_grant`, `AADSTS70000` |
| Corrupted authorization code | Token redemption failed | `invalid_grant`, `AADSTS70000` |
| Redeemed same code twice | Second redemption failed | `invalid_grant`, `AADSTS70000` |
| Mismatched redirect URI — token step | Request rejected | `invalid_request`, `AADSTS90023` |
| Mismatched redirect URI — authorize step | Request rejected | `invalid_request` |
| Changed `state` | Tokens were still issued | No Entra error |

---

# 9. Security Findings

## 9.1 Wrong PKCE verifier

Changing one character in the verifier caused token redemption to fail.

Entra reported:

```text
The provided 'code_verifier' input value does not match
the original 'code_challenge'.
```

This demonstrates that the authorization code is bound to the original PKCE challenge.

---

## 9.2 Missing PKCE verifier

Removing the verifier also caused redemption to fail.

This is important because allowing the verifier to be omitted would effectively create a downgrade path where an attacker with a stolen authorization code could attempt to redeem it without PKCE.

---

## 9.3 Authorization code replay

Redeeming the same authorization code twice failed.

Entra reported the code as invalid/expired.

The error message did not explicitly distinguish replay from timeout, so the experiment demonstrates that the code could not be reused, but the error message alone does not prove the exact internal reason.

---

## 9.4 Redirect URI mismatch

A mismatched redirect URI was rejected.

The redirect URI was validated during both the authorization and token stages.

The token endpoint returned:

```text
invalid_request
AADSTS90023
```

This demonstrates that the redirect URI is part of the trust relationship between the client and Entra.

---

## 9.5 `state` manipulation

Changing the `state` value did **not** cause Entra to reject the request.

Entra returned the modified value and still issued tokens.

This demonstrated that Entra does not validate the application's `state` value.

The client application is responsible for:

1. Generating a random `state`.
2. Storing the value associated with the authorization request.
3. Comparing the returned `state` with the original value.
4. Rejecting the response if they do not match.

This is separate from PKCE.

---

# 10. Important Observations

### Error codes are not always sufficient

`AADSTS70000` was observed for several different conditions:

- Wrong verifier
- Missing verifier
- Invalid authorization code
- Authorization-code replay

The descriptive error message was therefore more useful than the error code alone.

### Change one variable at a time

Several confusing results occurred during early experimentation.

Changing only one variable per test made the results much easier to interpret.

This is an important lesson for security testing generally:

> Establish a baseline, change one variable, observe the result, and document it.

---

# 11. Things I Could Not Fully Explain

I deliberately recorded observations that I could not explain rather than inventing explanations.

### Authorization code character change

Changing one character near the end of the authorization code was accepted, while changing a character in the middle caused the code to fail.

A possible explanation is related to the internal encoding/representation of Microsoft's authorization code, but this was not investigated further.

I therefore do not consider this a confirmed finding.

### Unexpected wrong-verifier result

An early wrong-verifier test produced an unexpected result.

I could not reproduce it.

A clean, controlled wrong-verifier test subsequently failed as expected, so I treated the original result as an unexplained test/setup issue rather than a security finding.

---

# 12. Security Mental Model

The main mental model I took away from this lab is:

```text
PKCE
 └── Protects authorization-code redemption
     └── Validated by Entra


state
 └── Correlates authorization request and response
     └── Validated by the client application


nonce
 └── Binds the ID token to the authentication request
     └── Validated by the client application


redirect_uri
 └── Restricts where authorization responses may be sent
     └── Validated by Entra


ID token
 └── Intended for the client application


Access token
 └── Intended for the resource/API
```

---

# 13. What I Learned

- How the OAuth 2.0 Authorization Code Flow works at the protocol level.
- How PKCE protects authorization-code redemption.
- Why the `code_challenge` is sent before the `code_verifier`.
- The different security roles of PKCE, `state`, and `nonce`.
- The distinction between ID tokens and access tokens.
- That access tokens may be opaque rather than JWTs.
- How redirect URI validation contributes to the security of the flow.
- That authorization codes cannot simply be reused.
- That a single OAuth error code can represent multiple underlying failures.
- The importance of changing one variable at a time during security experiments.

---

# 14. Next Steps

This lab provides the protocol foundation for the next set of identity-security exercises.

Planned areas:

- Microsoft Entra application security
- Delegated vs. application permissions
- OAuth consent
- Service principals
- Application secrets and certificates
- Microsoft Graph permissions
- Identity attack paths
- AWS IAM
- Identity security assessment
