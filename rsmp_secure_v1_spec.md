# Secure RSMP v1 - draft

## 1. Scope

This document specifies `rsmp-secure-v1`, an end-to-end authenticated and encrypted transport profile for RSMP. It defines:

- the security properties and trust boundary;
- the fixed EDHOC and COSE algorithms;
- the credential and authorization model;
- the deterministic-CBOR wire format;
- initial channel establishment;
- traffic-key derivation and data protection;
- replay protection and traffic-key renewal; and
- conformance and operational requirements.

The profile protects complete RSMP JSON messages between the two RSMP endpoints that terminate the secure channel. It does not change the syntax or semantics of RSMP messages after decryption.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in BCP 14 when, and only when, they appear in capitals.

## 2. Security model

### 2.1 Goals

Secure RSMP v1 provides:

- mutual authentication of provisioned RSMP endpoints;
- confidentiality and integrity of complete RSMP messages;
- cryptographic binding of the channel to both credential identities and the selected profile;
- authorization of the authenticated credential for one RSMP identity, role, and Core version;
- ordered delivery and replay rejection within each traffic-key epoch;
- independent traffic keys and nonces for each direction;
- forward secrecy from ephemeral X25519 key agreement;
- periodic replacement of traffic keys; and
- fail-closed behavior on authentication, framing, authorization, replay, or rekey failure.

### 2.2 Trust boundary

The protected path begins and ends at the processes that hold the long-term private keys and terminate EDHOC and COSE. An intermediary preserves end-to-end protection only if it forwards Secure RSMP frames unchanged. Any component that decrypts, translates, inspects plaintext, or re-encrypts traffic is a trusted endpoint and requires a separate Secure RSMP channel on each side.

The profile assumes that peer credentials and authorization policy are provisioned through an authenticated administrative process. A pinned credential is a trust anchor; possession of a syntactically valid credential is not sufficient.

### 2.3 Threats and limitations

The profile protects against passive observation, message modification, message injection, replay, and impersonation by a party that does not possess a trusted private key.

It does not protect against compromise of either endpoint, theft of an active endpoint's long-term private key, denial of service, traffic analysis, or disclosure through RSMP application behavior. Frame lengths and timing remain observable. Secure RSMP v1 defines no padding.

An attacker that records traffic and later obtains a long-term private key cannot derive past traffic keys from completed uncompromised EDHOC exchanges. Compromise of an endpoint while traffic secrets are resident can expose the corresponding active epoch.

## 3. Fixed cryptographic profile

An implementation claiming conformance to `rsmp-secure-v1` **MUST** use exactly the following profile:

| Function | Requirement |
| --- | --- |
| EDHOC | RFC 9528 method 0 |
| EDHOC cipher suite | Suite 4 |
| Ephemeral key agreement | X25519 |
| Endpoint signatures | Ed25519 with EdDSA |
| Hash and HKDF | SHA-256 and HKDF-SHA-256 |
| EDHOC AEAD | ChaCha20/Poly1305 |
| RSMP data protection | Untagged `COSE_Encrypt0` |
| COSE algorithm | ChaCha20/Poly1305, algorithm 24 |
| Encoding | Deterministic CBOR |

The profile name is the exact UTF-8 string `rsmp-secure-v1`, and the Secure RSMP wire version is the integer `1`.

The offered EDHOC method list **MUST** be `[0]`, and the offered cipher-suite list **MUST** be `[4]`. Implementations **MUST NOT** negotiate, accept, or fall back to another method, cipher suite, profile, or plaintext RSMP on the same connection.

Secure RSMP v1 **MUST NOT** send or accept EDHOC External Authorization Data (EAD), whether critical or non-critical. Algorithm agility, alternate credentials, or post-quantum mechanisms require a separately named future profile with independent conformance rules. Such a profile **MUST NOT** introduce downgrade negotiation into `rsmp-secure-v1`.

## 4. Transport framing and CBOR

Every Secure RSMP frame is encoded as:

1. a four-byte unsigned big-endian length; followed by
2. exactly that many bytes of deterministic CBOR.

The length counts the CBOR bytes only. A frame **MUST NOT** exceed 65,536 CBOR bytes. A receiver **MUST** reject an oversized, truncated, non-deterministic, or malformed frame and close the connection.

All maps defined by this specification are closed maps: a conforming sender **MUST** include every specified field exactly once and **MUST NOT** include unknown fields. A receiver **MUST** reject missing, duplicate, or unknown fields, wrong CBOR types, non-minimal integer encodings, and non-deterministic map ordering.

The following CDDL is an overview of the outer frame family:

```cddl
secure-message = edhoc-frame / edhoc-error-frame / data-frame / rekey-frame

edhoc-frame = {
  "v": 1,
  "type": "edhoc",
  "profile": "rsmp-secure-v1",
  "msg": 1 / 2 / 3 / 4,
  "edhoc": bstr
}

edhoc-error-frame = {
  "v": 1,
  "type": "edhoc_error",
  "profile": "rsmp-secure-v1",
  "edhoc": bstr
}

data-frame = {
  "v": 1,
  "type": "data",
  "epoch": 0..18446744073709551615,
  "enc": cose-encrypt0
}

rekey-frame = {
  "v": 1,
  "type": "rekey",
  "epoch": 0..18446744073709551615,
  "enc": cose-encrypt0
}
```

The `edhoc` byte string is the complete EDHOC message. The Secure RSMP wrapper is not part of the EDHOC transcript. Its `v`, `type`, `profile`, and `msg` fields are validated before the EDHOC bytes are processed.

## 5. Credentials, trust, and authorization

### 5.1 Credential format

Each endpoint has one Ed25519 private key and one exact, deterministic-CBOR CCS credential. The private-key file contains the 32-byte Ed25519 private seed followed by the corresponding 32-byte public key. It **MUST** be kept confidential and **MUST NOT** be carried on the wire or included in the credential.

The `.cred` file is exactly:

```cddl
kid = bstr .size 16

ccs-credential = {
  2: subject,
  8: {
    1: {
       1: 1,
       2: kid,
      -1: 6,
      -2: bstr .size 32
    }
  }
}

subject = tstr
```

The integer labels have the following meanings:

- CWT claim `2` is the non-empty UTF-8 credential subject;
- CWT confirmation claim `8`, key `1`, contains the `COSE_Key`;
- COSE key type `1` is OKP;
- COSE curve `6` is Ed25519;
- COSE key parameter `-2` is the raw 32-byte public key; and
- COSE key parameter `2` is the KID.

The KID **MUST** equal the first 16 bytes of `SHA-256(raw_ed25519_public_key)`. The optional COSE `alg` parameter is omitted because EDHOC suite 4 fixes the signature algorithm.

The credential **MUST** contain exactly these fields. It is neither self-signed nor wrapped in `COSE_Sign1`. Trust is established by pinning the complete `.cred` bytes through an authenticated provisioning process.

At startup, an implementation **MUST** verify deterministic encoding, exact map shape, subject validity, key and KID lengths, derived KID correctness, correspondence between the local private and public key, and correspondence between the local public key and local credential. Duplicate trusted subjects or duplicate trusted KIDs **MUST** be rejected.

### 5.2 EDHOC authentication

The endpoint sends its credential by EDHOC KID reference and authenticates possession of the corresponding Ed25519 private key. A receiver **MUST** resolve a received KID only against its locally pinned credentials and **MUST NOT** import or trust credential material supplied by the peer outside this resolution.

The cryptographic EDHOC initiator is the side that opens the TCP connection. The EDHOC role is independent of whether the application endpoint is an RSMP site or supervisor.

Each initial or rekey EDHOC session **MUST** use a freshly generated, unpredictable four-byte connection identifier and fresh ephemeral key material.

### 5.3 RSMP authorization

Authentication proves possession of a pinned credential. Authorization separately determines which RSMP identity that credential may use.

Local policy **MUST** map each trusted credential subject to exactly one expected RSMP identity and role, and **MAY** restrict the permitted RSMP Core versions. Policy is deny-by-default. Identity comparisons use exact, non-empty UTF-8 strings.

Before opening TCP, the connector **MUST** select the intended peer's pinned credential from the connection configuration. During EDHOC it **MUST** verify the responder against that pin before sending EDHOC message 3. A listener serving several peers **MUST** select the policy entry by the authenticated initiator credential and verify that the entry is permitted on this connection before exchanging RSMP messages. Both endpoints **MUST** enforce the configured peer role. On a site-to-site connection both endpoints are sites, and the connection configuration assigns the leader and follower roles. A missing policy entry, a different pin, or a role mismatch is connection-fatal.

After the EDHOC handshake, the site **MUST** send one encrypted RSMP `Version` request and the supervisor **MUST** answer an accepted request with one encrypted `Version` response. For site-to-site communication, the follower sends the request and the leader sends the response. These application roles apply in either TCP connection direction. Until local authorization completes, the only permitted RSMP messages are this request, this response, and their `MessageAck` or `MessageNotAck` acknowledgements.

For each received `Version`, the receiver first identifies the expected request or response from the application roles and exchange sequence and reads the offered Core versions. It **MUST** then validate the complete message against the selected Core version before SXL negotiation, authorization, or positive acknowledgement. In Core 3.3.0, `step` must match the expected `Request` or `Response`. Earlier Core versions without `step` use the roles and sequence alone. If Core validation fails, the receiver **MUST** follow the applicable Core rejection procedure and close the connection.

The authorized peer identity always comes from the policy entry for the authenticated credential. After Core validation, the receiver **MUST** apply the following identity checks for the selected Core version:

| Received message | Core 3.3.0 | Earlier Core versions using `siteId` in both messages (including 3.2.2) |
| --- | --- | --- |
| Request from site or follower | The sole `siteId[0].sId` must equal the requesting peer's authorized site identity. | Apply the same check. Secure RSMP requires exactly one entry even when Core permits several. |
| Response from supervisor or leader | Core requires a non-empty `supervisorId` string. Its value is informational. A valid value may differ from the authorized peer identity and **MUST NOT** affect authorization. | The response's `siteId` must contain exactly one entry whose `sId` equals the site or follower identity in the original request. The receiver authorizes the supervisor or leader using its credential policy entry. |

A missing required field or a failed site identity check **MUST** trigger the applicable Core rejection procedure and close the connection. A selected Core version outside the peer's permitted versions is also connection-fatal. Neither a request nor a response may select a different credential policy entry.

Each endpoint **MUST** verify that local policy authorizes the authenticated peer for the RSMP identity, role, and selected Core version before sending a `MessageAck` for the peer's `Version`. When receiving a `MessageAck` or `MessageNotAck` during this exchange, the endpoint **MUST** match its `oMId` to the `mId` of its own outstanding `Version`. An unexpected acknowledgement or a `MessageNotAck` for either `Version` is connection-fatal.

Local authorization completes only when the endpoint has accepted and acknowledged the peer's `Version` and received a matching `MessageAck` for its own `Version`. Only then may it send or dispatch the next RSMP message in the selected Core version's startup sequence.

The resulting authorization context consists of:

- authenticated credential subject;
- authorized RSMP identity;
- authorized site or supervisor role, including the configured leader or follower role on a site-to-site connection; and
- selected RSMP Core version.

This context **MUST** be immutable for the lifetime of the connection. A repeated `Version` request, a repeated `Version` response, a `Version` from the wrong role, or any attempt to renegotiate the identity, role, or Core version **MUST** close the secure connection. A different context requires a new TCP connection and a new initial EDHOC exchange.

## 6. Initial channel establishment

The initial handshake always contains all four EDHOC messages:

```text
TCP/EDHOC initiator                         TCP/EDHOC responder
        |                                             |
        |-- edhoc(msg=1, EDHOC message_1) ---------->|
        |<--------- edhoc(msg=2, EDHOC message_2) ----|
        |-- edhoc(msg=3, EDHOC message_3) ---------->|
        |<--------- edhoc(msg=4, EDHOC message_4) ----|
```

EDHOC message 4 is **REQUIRED**. Neither endpoint may create the application transport, send `data` or `rekey` frames, or process RSMP messages until message 4 has been successfully authenticated.

A receiver expects the message numbers in the sequence shown above. An unexpected number, frame type, profile, version, field, or EDHOC state transition is fatal.

After EDHOC completes, the encrypted RSMP exchange in Section 5.3 proceeds by application role. In this successful exchange, A and B represent the two distinct RSMP message IDs.

```text
Site or follower                             Supervisor or leader
      |-- Version request  (mId=A) ------------------>|
      |<----------------------- MessageAck (oMId=A) --|
      |<----------------- Version response (mId=B) ---|
      |-- MessageAck (oMId=B) ----------------------->|
```

### 6.1 Handshake errors

If a failure follows receipt of a structurally valid `edhoc` or `edhoc_error` wrapper, the endpoint **MAY** send at most one `edhoc_error` frame containing an RFC 9528 EDHOC error message. It **MUST** use the generic unspecified error code and generic text `EDHOC handshake failed`, then close the connection.

Malformed input that has not established a valid Secure RSMP handshake wrapper **MUST** be closed without a response. An endpoint receiving an `edhoc_error` **MUST NOT** answer it with another error. Diagnostic detail may be recorded locally but **MUST NOT** be exposed to the unauthenticated peer.

The complete initial handshake **MUST** finish within two seconds. Timeout is fatal and closes the connection.

## 7. Exporter and key schedule

After authentication, each endpoint constructs the same deterministic-CBOR exporter context:

```cddl
rsmp-context = {
  "context": "rsmp-secure-v1",
  "profile": "rsmp-secure-v1",
  "initiator": tstr,
  "responder": tstr,
  "connection": {
    "socket": "single-rsmp-connection"
  }
}
```

`initiator` and `responder` are the authenticated credential subjects in EDHOC-role order. Both are mandatory, non-empty UTF-8 strings.

The deterministic-CBOR bytes are passed to RFC 9528:

```text
exporter_result = EDHOC_Exporter(
  label   = 32768,
  context = deterministic_cbor(rsmp-context),
  length  = 32
)
```

Label 32768 is a private-use label. OSCORE exporter labels 0 and 1 **MUST NOT** be used.

Both HKDF stages use the following `info` structures. The `rsmp_context` field is a CBOR byte string containing the same context bytes supplied to the exporter.

```cddl
traffic-secret-info = {
  "context": "rsmp-secure-v1 hkdf",
  "label": "traffic secret",
  "rsmp_context": bstr .cbor rsmp-context
}

labeled-info = {
  "context": "rsmp-secure-v1 hkdf",
  "label": "session id" / "i2r key" / "r2i key" /
           "i2r nonce" / "r2i nonce"
}
```

Endpoints **MUST** apply full RFC 5869 HKDF-SHA-256 at each stage. In the equations below, `h''` is an empty byte string, lengths are in bytes, and `labeled-info(label)` is the map above with the indicated text string as its `label` value.

```text
HKDF(ikm, info, length) = HKDF-Expand(HKDF-Extract(h'', ikm), info, length)

traffic_secret = HKDF(exporter_result, deterministic_cbor(traffic-secret-info), 32)
derive(label, length) = HKDF(traffic_secret, deterministic_cbor(labeled-info(label)), length)

session_id       = derive("session id", 16)    # initial exchange only
i2r_key          = derive("i2r key", 32)
r2i_key          = derive("r2i key", 32)
i2r_nonce_prefix = derive("i2r nonce", 8)
r2i_nonce_prefix = derive("r2i nonce", 8)
```

`i2r` denotes the EDHOC initiator-to-responder direction and `r2i` the reverse. On every rekey, endpoints **MUST** derive a new traffic secret from the fresh EDHOC exporter result, derive both keys and both nonce prefixes from that secret, and retain the initial session ID.

### 7.1 Key schedule test vector

For the initial exchange, use credential subjects `RN+SI0001` (initiator) and `supervisor` (responder) and the fixed 32-byte exporter result `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`. The expected outputs are hexadecimal.

| Output | Expected bytes |
| --- | --- |
| `traffic_secret` | `fba533cce9ad914357386290334a2f577a9848b91d2545c44c7b46f5fa06ba97` |
| `session_id` | `a2053e954f583bd8bd340a2e67629ff5` |
| `i2r_key` | `438e9532ddc32f0ed178b4630dbf2997a3acaa57be909117f845e11b3551ff4d` |
| `r2i_key` | `641bb113a1fd043d7aa266d25a75f7dede88221cc5e5b90df119a2ed5d0bca37` |
| `i2r_nonce_prefix` | `8bb798819d9ec4a8` |
| `r2i_nonce_prefix` | `9df78ed6937d1eab` |

## 8. Protected RSMP data

Each complete RSMP JSON object is converted to deterministic CBOR and protected as one `data` frame. Splitting one RSMP message across multiple Secure RSMP frames is not defined.

The `enc` field is an untagged RFC 9052 `COSE_Encrypt0` array:

```cddl
cose-encrypt0 = [
  protected: bstr .cbor {1: 24},
  unprotected: {6: bstr .size (1..4)},
  ciphertext: bstr
]
```

The protected header contains only COSE algorithm 24. The unprotected header contains only Partial IV label 6. The Partial IV is the minimal, unsigned, big-endian encoding of a frame index from 1 through 4,294,967,295.

Each direction has an independent frame index, beginning at 1 in every epoch. A receiver accepts only the next exact index. Duplicate, skipped, reordered, zero, non-minimal, oversized, or exhausted indices are fatal. An index **MUST NOT** wrap or be reused with the same traffic key.

The 12-byte ChaCha20/Poly1305 nonce is constructed by appending four zero bytes to the eight-byte directional nonce prefix, left-padding the Partial IV to 12 bytes, and XORing the two values.

The COSE external AAD is the deterministic-CBOR encoding of:

```cddl
secure-aad = {
  "context": "rsmp-secure-data-v1",
  "connection": "single-rsmp-connection",
  "epoch": 0..18446744073709551615,
  "idx": 1..4294967295,
  "sender": "i2r" / "r2i",
  "session": bstr .size 16,
  "type": "data" / "rekey"
}
```

The AEAD AAD is the RFC 9052 `Enc_structure`:

```cddl
[
  "Encrypt0",
  protected,
  deterministic_cbor(secure-aad)
]
```

This binds the ciphertext to the session, direction, epoch, index, and frame family. The outer map is parsed for dispatch, but its security-relevant values are independently authenticated through this AAD.

The plaintext recovered from a `data` frame **MUST** decode as exactly one deterministic-CBOR map. After decoding, the map is dispatched as one RSMP message and is subject to the normal RSMP Core and SXL validation and error-handling rules. Unauthenticated plaintext **MUST NOT** reach the RSMP dispatcher.

A deterministic-CBOR decoding failure, COSE authentication failure, replay or ordering failure, authorization failure, or violation of Secure RSMP connection state **MUST** close the connection. After authorization has completed, an RSMP Core or SXL schema or semantic validation failure **MUST** be handled according to the applicable RSMP specification, including sending `MessageNotAck` where required. Sending or receiving an ordinary post-authorization `MessageNotAck` **MUST NOT** by itself close or rekey the secure channel. Failure of the initial `Version` exchange, a repeated request or response, or attempted renegotiation is connection-fatal as specified in Section 5.3.

## 9. Traffic-key epochs and renewal

### 9.1 Epochs and mandatory limits

The initial channel uses epoch 0. Each successful rekey increments the epoch by exactly one. The epoch is an unsigned 64-bit integer and **MUST NOT** wrap. At epoch 18,446,744,073,709,551,615 the endpoint **MUST** reconnect before sending more protected traffic.

An implementation **MUST** complete a rekey before any one of these per-direction, per-epoch limits is exceeded:

| Limit | Maximum |
| --- | ---: |
| Protected frames | 1,000,000 |
| Ciphertext bytes, including AEAD tags | 68,719,476,736 bytes (64 GiB) |
| Epoch lifetime | 7,200 seconds (2 hours) |

Deployments **MAY** configure lower limits but **MUST NOT** disable a limit or configure a higher one. The message limit **MUST** be at least 3. The byte limit **MUST** reserve space for two maximum-sized old-epoch control frames. Rekey scheduling **MUST** reserve two old-epoch frame indices and sufficient bytes for the remaining control exchange. The rekey timeout is exactly two seconds, and time-based rekey starts sufficiently early to finish before the lifetime limit.

When any limit becomes due, application-data transmission stops until rekey succeeds. A failure, timeout, or inability to reserve safe nonce space is fatal.

### 9.2 Roles and request

Only the original EDHOC initiator may initiate a rekey EDHOC exchange. The responder requests renewal by sending an encrypted `rekey_request` under the current epoch. A request received while an initiator exchange is already pending or active is satisfied by that exchange and **MUST NOT** start a second one.

The decrypted control messages are closed maps:

```cddl
rekey-edhoc = {
  "kind": "rekey_msg1" / "rekey_msg2" / "rekey_msg3",
  "next_epoch": 0..18446744073709551615,
  "edhoc": bstr
}

rekey-simple = {
  "kind": "rekey_request" / "rekey_ack",
  "next_epoch": 0..18446744073709551615
}

rekey-error = {
  "kind": "rekey_error",
  "next_epoch": 0..18446744073709551615,
  "code": "failed"
}
```

All controls are carried in `rekey` frames protected by `COSE_Encrypt0`. Except for `rekey_ack`, they use the current epoch and current traffic keys. `next_epoch` **MUST** equal `current_epoch + 1`.

### 9.3 Rekey exchange

The exchange is:

```text
Original initiator                            Original responder
        |                                              |
        |<-- rekey_request (current keys, optional) ----|
        |-- rekey_msg1 (current keys) ----------------->|
        |<------------- rekey_msg2 (current keys) ------|
        |-- rekey_msg3 (current keys) ----------------->|
        |<================ rekey_ack (new keys) =========|
        |                                              |
```

The embedded EDHOC exchange uses the same fixed profile and pinned credentials as the initial exchange, but fresh connection identifiers and ephemeral keys. EDHOC message 4 is not embedded in rekey. Instead, the responder's `rekey_ack`, authenticated as the first protected frame under the new epoch keys, confirms successful installation and possession of the new traffic keys.

The responder authenticates EDHOC message 3, verifies that the credential subject is unchanged, derives and installs the new channel, then sends `rekey_ack` under the new keys. The initiator prepares a pending channel before sending message 3 but **MUST NOT** install it or resume application traffic until it authenticates the acknowledgement under the pending new keys.

The session id and authorization context remain unchanged. Frame indices reset independently to 1 in both directions. The previous channel's traffic secret, directional keys, and nonce prefixes **MUST** be erased after successful installation.

Rekey **MUST** complete within two seconds. A party that can still authenticate a control failure **SHOULD** send exactly one `rekey_error` with code `failed`; both parties then close the connection. Detailed cryptographic errors **MUST NOT** be exposed on the wire.

Unsolicited responses, wrong roles, wrong epochs, application data during required or active rekey, an acknowledgement under old keys, changed peer identity, or malformed controls are fatal.

## 10. Failure handling and operations

All security failures are connection-fatal. Implementations **MUST NOT** continue with degraded security, retry the connection as plaintext, skip a failed authorization check, reuse an epoch or frame index, or retain a partially established channel.

Long-term private keys, EDHOC session secrets, exporter results, traffic secrets, directional keys, and nonce prefixes **SHOULD** be erased as soon as they are no longer required. Implementations **SHOULD** use operating-system protections, restrictive file permissions, or hardware-backed key storage appropriate to the deployment.

Operational logs **SHOULD** record successful and failed authentication, authorization, rekey, credential selection, epoch changes, and reason categories. Logs **MUST NOT** contain private keys, traffic secrets, decrypted RSMP payloads unless explicitly required by policy, or peer-visible cryptographic diagnostics that create an oracle. Implementations **SHOULD** rate-limit repeated failed connection attempts.

Credential provisioning, replacement, revocation, backup, and recovery are administrative responsibilities. Changes to pinned credentials or authorization policy apply to new connections; an active connection **SHOULD** be closed when its credential is revoked.

## 11. Conformance requirements

A conforming implementation **MUST** test at least:

- exact deterministic-CBOR encoding and rejection of non-deterministic, duplicate, missing, and unknown fields;
- exact CCS shape, derived KID, key lengths, private/public match, duplicate subject, duplicate KID, and unknown peer rejection;
- fixed EDHOC method 0 and suite 4, four-message initial completion, EAD rejection, fresh connection identifiers, and generic error behavior;
- exporter context identity ordering and all six outputs of the Section 7 key schedule test vector;
- known-answer encryption/decryption, directional key separation, nonce construction, AAD binding, tag failure, replay, gaps, reordering, and index exhaustion;
- continued use of the same secure channel after an ordinary post-authorization `MessageNotAck`;
- one protected `Version` request and one response, each acknowledged by `oMId`, for both site-opened and supervisor-opened TCP connections and for follower/leader startup;
- selected-Core validation of both `Version` messages, including the expected `step` in Core 3.3.0 and role-based identification in supported earlier versions without `step`;
- outgoing rejection of a different locally pinned peer, listener selection by authenticated credential, and enforcement of the configured application role and permitted Core versions;
- acceptance of a single matching site ID in a site or follower request, rejection of missing, mismatched, or multiple IDs, and rejection of a legacy response whose sole site ID differs from the original request;
- authorization of the configured supervisor or leader when a valid Core 3.3.0 `supervisorId` differs from its policy identity, rejection of a missing required `supervisorId`, and authorization of a legacy responder from its pin when Core supplies no responder identity;
- authorization of identity, role, and Core version at each endpoint, including that an acknowledgement alone cannot complete authorization and that other RSMP traffic is gated until local completion;
- connection closure on a mismatched acknowledgement, a `MessageNotAck` for either `Version`, a repeated request or response, a wrong-role `Version`, or an attempt to change the authorization context;
- initiator- and responder-triggered rekey, simultaneous triggers, fresh keys, stable session id, changed-identity rejection, new-key acknowledgement, old-key erasure, and all three mandatory limits;
- rekey timeout, error control, invalid role, wrong epoch, unsolicited response, old-key acknowledgement, and data during rekey; and
- epoch values above 255, unsigned 64-bit exhaustion, and refusal to wrap.

The normative CDDL artifact is `schemas/secure/rsmp-secure-v1.cddl`. CDDL establishes structure; implementations remain responsible for every semantic and cryptographic check stated in this document.

## 12. Normative references

- RFC 2119 and RFC 8174, requirement language (BCP 14).
- RFC 5869, HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
- RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA).
- RFC 8152 and RFC 9052, CBOR Object Signing and Encryption (COSE).
- RFC 8610, Concise Data Definition Language (CDDL).
- RFC 8949, Concise Binary Object Representation (CBOR), including deterministic encoding.
- RFC 9053, COSE algorithms.
- RFC 9528, Ephemeral Diffie-Hellman Over COSE (EDHOC).
