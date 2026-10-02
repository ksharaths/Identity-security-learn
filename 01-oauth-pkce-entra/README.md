# OAuth 2.0 Authorization Code Flow with PKCE: Microsoft Entra

A hands-on lab implementing the OAuth 2.0 Authorization Code Flow with PKCE manually against Microsoft Entra, without MSAL or an SDK.

The goal was to understand the protocol at the request/response level, then deliberately break one security control at a time to see how Entra responds.

> **Transparency note:** I did the lab myself: app registration, running the commands, collecting results and running the experiments. AI assistance was used for guidance and starter code. The observations below come from my own runs.

**Scope of the findings:** everything here was tested with a **personal Microsoft account** against the `consumers` endpoint. Work or school (organizational) tenants can behave differently, for example in access token format and consent behavior, so treat these results as specific to this setup.

## Contents

1. [Environment](#1-environment)
2. [What PKCE is and why the hash goes first](#2-what-pkce-is-and-why-the-hash-goes-first)
3. [PKCE implementation](#3-pkce-implementation)
4. [`state`, `nonce` and PKCE](#4-state-nonce-and-pkce)
5. [Authorization request](#5-authorization-request)
6. [Token exchange](#6-token-exchange)
7. [Token analysis](#7-token-analysis)
8. [Breaking the flow](#8-breaking-the-flow)
9. [Findings](#9-findings)
10. [Observations about method](#10-observations-about-method)
11. [Things I could not explain](#11-things-i-could-not-explain)
12. [Mental model](#12-mental-model)
13. [What I learned](#13-what-i-learned)
14. [Next steps](#14-next-steps)

---

## 1. Environment

- Microsoft Entra ID, personal Microsoft account, free Azure trial
- App registration: **Mobile and desktop application / public client**
- Redirect URI: `http://localhost` (nothing listens on it, so the browser shows a connection error and the `code` can be read from the address bar)
- Python 3 (standard library only)
- PowerShell `curl.exe`, jwt.ms, Microsoft Graph `/me`

Scopes requested:

```text
openid offline_access User.Read
```

### Code

- `start.py`: generates a fresh verifier, `state` and `nonce`, and prints the authorize URL.
- Code redemption was done manually with PowerShell `curl.exe` (see section 6).

No secrets or real tokens are committed. 

---

## 2. What PKCE is and why the hash goes first

In the authorization code flow, the authorization code travels through the browser and could be intercepted. A public client has no client secret to prove its identity when redeeming the code.

PKCE adds a one-time secret, the `code_verifier`, and sends only its hash in the first step:

```text
1. Client generates a random code_verifier.
   code_challenge = BASE64URL( SHA-256( code_verifier ) )

2. Authorize request carries code_challenge  ->  Entra stores it.

3. Entra returns an authorization code via the browser redirect.

4. Token request carries code + code_verifier.

5. Entra computes SHA-256 of the verifier and compares it with the
   stored code_challenge. Only a match returns tokens.
```

### Why the hash goes first

The authorize request is sent through the browser as a GET request, so an attacker can capture it. The response comes back through the browser too, and it carries the authorization code, which can be redeemed for an `access_token`, `id_token` and `refresh_token`. If the `code_verifier` were sent in the authorize request, an attacker who captured it and the code would have everything needed to redeem the code and get the tokens. 

Sending the `code_challenge` (the hashed verifier) instead prevents this. The attacker may see the code and the challenge, but cannot redeem the code without the verifier. The verifier goes to the token endpoint later on the back channel. Entra hashes it and compares the result with the `code_challenge` from the authorize request, and only a match returns tokens. SHA-256 is a one-way function, so the attacker cannot derive the verifier from the challenge. This relies on the verifier being long and random, which is why the lab uses `secrets` rather than `random`.

---

## 3. PKCE implementation

```python
import secrets, hashlib, base64

code_verifier = secrets.token_urlsafe(64)

digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
```

Details that matter:

- `secrets`, not `random`: the verifier must be unpredictable.
- SHA-256 runs on the ASCII bytes of the verifier, using `.digest()` rather than `.hexdigest()`.
- Base64 **URL-safe** encoding, with the `=` padding stripped.
- A new verifier for every authorization attempt.

---

## 4. `state`, `nonce` and PKCE

Three values that look similar but guard different steps.

| Mechanism | Binds | Validated by |
| --- | --- | --- |
| `code_challenge` / `code_verifier` | authorize request to token redemption | Entra |
| `state` | authorize request to the redirect response | client app |
| `nonce` | authorize request to the ID token | client app |

---

## 5. Authorization request

Parameters:

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

Endpoint:

```text
https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize
```

After sign-in, Entra redirects to the registered redirect URI with `code` and `state` in the query string.

---

## 6. Token exchange

The code was redeemed at the token endpoint with `curl.exe`:

```text
grant_type=authorization_code
client_id=<CLIENT_ID>
code=<CODE>
redirect_uri=http://localhost
code_verifier=<VERIFIER>
```

The response contained `access_token`, `id_token`, `refresh_token` and `expires_in` (3599 seconds).

Gotcha: characters in the code such as `!` and `*` need careful shell quoting. In PowerShell, use single quotes around the code.

---

## 7. Token analysis

### ID token

Decoded with jwt.ms from a successful redemption. Unique values are redacted.

| Claim | Value | What I observed |
| --- | --- | --- |
| `ver` | `2.0` | Matches the v2.0 endpoint I used |
| `iss` | `https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0` | The tenant GUID is the shared consumer tenant for personal accounts, not a tenant of mine |
| `tid` | `9188040d-6c67-4c5b-b112-36a304b66dad` | Same GUID as in `iss`. An app limiting which tenants can sign in would check this |
| `aud` | `<CLIENT_ID>` | Matched my app registration |
| `sub` | `<redacted>` | Pairwise: differs from the Graph `/me` `id` |
| `iat` / `nbf` | same time | Identical |
| `exp` | about 24 h after `iat` | Much longer than the access token's 3599 s |
| `nonce` | `<redacted>` |  Present; not compared". |
| `aio` | `<redacted>` | Internal Entra claim, not for the app to use |

### Access token

jwt.ms could not decode the access token. Rather than assume it was broken, I tested it against Microsoft Graph:

```text
GET https://graph.microsoft.com/v1.0/me
Authorization: Bearer <ACCESS_TOKEN>
```

The call returned my profile, so the token was valid.

- **ID token:** meant for the client app to read.
- **Access token:** meant for the resource (here Graph). The client should not assume it is a JWT or try to interpret it.

I therefore did not observe an `scp` claim in this lab.

---

## 8. Breaking the flow

Each experiment used a fresh sign-in and changed one variable.

| Experiment | Result | Error | Error Description |
| --- | --- | --- | --- |
| Wrong verifier | Redemption failed |  `invalid_grant`, `AADSTS70000` | The provided 'code_verifier' input value does not match the original 'code_challenge.' |
| No verifier | Redemption failed | `invalid_grant`, `AADSTS70000` | The provided 'code_verifier' input value does not match the original 'code_challenge.' |
| Corrupted authorization code | Redemption failed | `invalid_grant`, `AADSTS70000` | The provided value for the 'code' parameter is not valid. |
| Same code redeemed twice | Second redemption failed | `invalid_grant`, `AADSTS70000` | The provided value for the 'code' parameter is not valid. The code has expired. |
| Redirect URI mismatch, authorize step | Rejected in the browser  | `invalid_request`, No error code | The provided value for the input parameter 'redirect_uri' is not valid. The expected value is a URI which matches a redirect URI registered for this client application. |
| Redirect URI mismatch, token step | Redemption failed| `invalid_request`, `AADSTS90023` | The provided value for the input parameter 'redirect_uri' is not valid. The expected value is a URI which matches a redirect URI registered for this client application. |
| `state` edited by hand | Tokens still issued | None | No Entra error. The check is the client's job. |

---

## 9. Findings

### 9.1 Wrong PKCE verifier

Changing one character of the verifier made redemption fail. Entra reported that the `code_verifier` does not match the original `code_challenge`. The authorization code is bound to the challenge it was issued against.

### 9.2 Missing PKCE verifier

Leaving the verifier out also failed. This matters because if omission were allowed, an attacker with a stolen code could simply skip PKCE (a downgrade).

### 9.3 Authorization code replay

Redeeming the same code twice failed, and Entra described the code as invalid or expired. The message does not separate "already used" from "timed out", so this shows the code cannot be reused, but not the exact internal reason.

### 9.4 Redirect URI mismatch

A mismatched `redirect_uri` was rejected at both steps. At the authorize step the request failed in the browser with `invalid_request` and no `AADSTS` code. At the token step the response was `invalid_request` with `AADSTS90023`. Both described the expected value as a URI matching one
registered for the client application.

The redirect URI is checked at both stages, so it is part of the trust relationship between the client and Entra.

### 9.5 `state`

I edited `state` in the redirect URL by hand and redeemed the code anyway. Entra still issued tokens, because `state` is never sent to the token endpoint. Entra only echoes it back in the redirect, so it cannot detect tampering. Detecting it is the client's job:

1. Generate a random `state` per request.
2. Store it.
3. Compare the returned value with the stored one.
4. Reject the response on any mismatch.

This is separate from PKCE. `redeem.py` implements the comparison.

---

## 10. Observations about method

**Error codes are not always enough.** `AADSTS70000` appeared for several different failures, so the descriptive message was more useful than the code. 

**Change one variable at a time.** Several confusing early results came from changing two things at once.

> Establish a baseline, change one variable, observe, document.

---

## 11. Things I could not explain

I recorded these instead of inventing explanations.

**Authorization code character change.** When the character near the end of the code, just before the trailing `$$` was changed, I still received valid tokens. I couldn't explain why this is so.  

---

## 12. Mental model

| Control | Protects | Validated by |
| --- | --- | --- |
| PKCE | authorization code redemption | Entra |
| `state` | request and response correlation | client |
| `nonce` | ID token tied to the request | client |
| `redirect_uri` | where responses may be sent | Entra |
| ID token | audience: the client app | client |
| Access token | audience: the resource/API | resource |

---

## 13. What I learned

- The oauth flow including the various components like resource owner, client, authorization server and resource server. Learned that authorize request goes over the `front channel`(browser) and the token request goes over the `back channel` 
- The authorize request parameters - `client_id`, `response_type`, `state`, `nonce`, `scope`, `redirect_uri`, `code_challenge`, & `code_challenge_method`.
- The token request parameters - `code`, `grant_type`, `code_verifier`, `redirect_uri` & `client_id`
- The role of PKCE, i.e., how `code_verifier` and `code_challenge` ensure that the `code` even when intercepted cannot be used by an attacker to get tokens.
- I also learned that resending the same code, changing the `verifier`, or modifying the `code` results in `invalid_grant` error. Modifying the `redirect_uri` returns the `invalid_request` error, with clear description of what error occurred in the response.Modifying the redirect_uri returned invalid_request. Each response had a clear description of the error.
- Interestingly, when the character near the end of the code, just before the trailing `$$` was changed, I still received valid tokens. I couldn't explain why this is so.  
- Entra does not check `state`. It never receives it at the token step. The client has to verify that they match and reject the response when they do not match.
- In my run, the personal-account access token was not a decodable JWT, but it worked fine against Graph.

---

## 14. Next steps

- JWT signature verification and the OIDC discovery document (JWKS)
- Refresh tokens and sessions
- Microsoft Entra application security
- Delegated vs. application permissions, OAuth consent, service principals
- Application secrets and certificates
- Microsoft Graph permissions
- Identity attack paths
- AWS IAM
- Identity security assessment
