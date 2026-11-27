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

In EDHOC message 1, `METHOD` **MUST** be the CBOR integer `0` and `SUITES_I` **MUST** be the CBOR integer `4`. These are the first two items of the RFC 9528 CBOR Sequence, so the embedded EDHOC bytes begin with hex `00 04`. A receiver **MUST** reject an array in either position. This encoding applies to both initial establishment and rekey. Implementations **MUST NOT** negotiate, accept, or fall back to another method, cipher suite, profile, or plaintext RSMP on the same connection.

Secure RSMP v1 **MUST NOT** send or accept EDHOC External Authorization Data (EAD), whether critical or non-critical. Algorithm agility, alternate credentials, or post-quantum mechanisms require a separately named future profile with independent conformance rules. Such a profile **MUST NOT** introduce downgrade negotiation into `rsmp-secure-v1`.

## 4. Transport framing and CBOR

Every Secure RSMP frame is encoded as:

1. a four-byte unsigned big-endian length; followed by
2. exactly that many bytes of deterministic CBOR.

The length counts the CBOR bytes only. During the initial EDHOC handshake, a frame **MUST NOT** exceed 65,536 CBOR bytes (64 KiB), including the wrapper. This limit applies through message 4 and to initial handshake errors. It ends at the endpoint's local handshake completion event in Section 6.

After initial EDHOC completion, the four-byte prefix can represent up to 4,294,967,295 CBOR bytes. The profile imposes no additional frame-size cap. This rule applies from the first protected `Version` message and throughout rekey. An endpoint **MAY** enforce local send and receive limits according to its available resources.

The receiver **MUST** check the declared length against the applicable limit before allocating a buffer for the declared size or reading the frame body. An oversized, truncated, non-deterministic, or malformed frame **MUST** close the connection.

The maps defining the security envelope, credentials, key derivation inputs, authenticated data, and rekey controls are closed. A sender **MUST** include exactly the specified fields, each once. A receiver **MUST** reject missing, duplicate, or unknown fields, wrong CBOR types, non-minimal integer encodings, and non-deterministic map ordering. Section 8.1 defines the application payload. The selected RSMP Core version and SXL determine how to handle its attributes.

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

EDHOC message 4 is **REQUIRED** for initial establishment. The responder completes its handshake when it has authenticated message 3 and successfully sent the complete message 4 frame. The initiator completes its handshake when it has received and successfully verified message 4. Each endpoint **MUST** reach its own completion event before creating the application transport, sending `data` or `rekey` frames, or processing RSMP messages.

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

During initial establishment, an invalid frame or wrapper, an unexpected frame type or message number, or receipt of an `edhoc_error` **MUST** close the connection without a reply. A timeout while waiting for the next message also closes the connection without a reply.

Once the expected `edhoc` wrapper has passed validation, a failure to decode or process its embedded EDHOC message **MUST** produce one `edhoc_error` reply followed by connection closure, subject to the error-suppression provisions of RFC 9528 Section 6 (for example, denial-of-service protection). The wrapper's `edhoc` byte string contains the RFC 9528 CBOR Sequence of `ERR_CODE` followed by `ERR_INFO`. Senders **MUST** use the following values:

| Failure | `ERR_CODE` | `ERR_INFO` |
| --- | ---: | --- |
| A well-formed message 1 selects an unsupported cipher suite (RFC 9528 Section 6.3) | 2 | Integer `4`, the only supported suite |
| Message 2 or 3 references a KID for which the receiver has no credential (RFC 9528 Section 6.4) | 3 | CBOR simple value `true` |
| Other failures, including a malformed embedded message, unsupported credential identifier type, or signature verification failure | 1 | Text string `EDHOC handshake failed` |

Additional diagnostics stay local. An error reply terminates this exchange and **MUST NOT** trigger a retry with different parameters or a fallback to plaintext. Errors during encrypted rekey use the control defined in Section 9.3.

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

### 8.1 RSMP application payload

The plaintext **MUST** contain exactly one untagged CBOR map with no trailing bytes. At every nesting level, senders and receivers **MUST** apply the core deterministic encoding requirements, including definite lengths, the shortest permitted encodings, and bytewise lexicographic order of the encoded map keys. [RFC 8949 §4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1)

| JSON value | CBOR representation |
| --- | --- |
| Object | Map with unique UTF-8 text keys. Compare decoded names by Unicode scalar sequence, without normalization. Reject duplicates before constructing a map that could discard them. In JSON input, `"a"` and `"\u0061"` are the same name. |
| Array | Array in the original element order. Apply these rules to every element. |
| String | UTF-8 text with the same Unicode scalar sequence. This includes timestamps, base64 data, and legacy values such as `"1.0"`. |
| Boolean or null | The corresponding CBOR `true`, `false`, or `null`. |
| Number without a fraction or exponent | Exact CBOR integer (major type 0 or 1) from −2⁶⁴ through 2⁶⁴−1, inclusive. JSON `-0` encodes as integer zero. Reject integers outside this range. |
| Number with a fraction or exponent | Convert to IEEE 754 binary64 using round-to-nearest, ties-to-even. Reject overflow and a nonzero input that rounds to zero. Encode the finite result in the shortest of binary16, binary32, or binary64 that preserves its value and its zero sign. |

Only these CBOR representations are permitted. Byte strings, tags, non-text keys, undefined, other simple values, NaNs, and infinities are invalid anywhere in the payload. A sender **MUST** reject an unrepresentable outbound message before sending a frame or consuming a frame index.

The receiver **MUST** preserve the integer or float form through RSMP validation. If it serializes a float back to JSON, it **MUST** include a fraction or exponent and enough digits to recover the same binary64 value, including the sign of zero. For example, `1.0` and `1e0` encode identically. Both remain distinct from integer `1`.

These examples show the complete plaintext bytes for a one-member object:

| JSON input | CBOR hex |
| --- | --- |
| `{"v":1}` | `a1 61 76 01` |
| `{"v":1.0}` or `{"v":1e0}` | `a1 61 76 f9 3c 00` |
| `{"v":-0.0}` | `a1 61 76 f9 80 00` |
| `{"v":"1.0"}` | `a1 61 76 63 31 2e 30` |

A receiver **MUST** close the connection if authenticated plaintext violates this mapping. Only an authenticated payload that satisfies the mapping may reach RSMP validation. A representable value in the wrong RSMP field type, such as a float in an integer-only field, is an RSMP validation failure. The receiver handles unknown application attributes according to the selected Core version and applicable SXL.

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

Deployments **MAY** configure lower limits but **MUST NOT** disable a limit or configure a higher one. Each endpoint **MUST** reject a configuration that fails any of the following conditions:

- The frame limit is at least 4 per direction. In a renewed epoch the responder needs room for the opening `rekey_ack`, one application frame, and two controls for the next renewal (`rekey_request` and `rekey_msg2`).
- The ciphertext byte limit covers the largest `rekey_ack`, the largest application frame the endpoint will send, and two maximum-sized old-epoch controls it can send during renewal. Count only the ciphertext field including its AEAD tag for each frame. Use the endpoint's outbound sizes for this calculation. The initial handshake cap does not apply to these frames.
- The epoch lifetime leaves time to send at least one application frame under the deployment's operating conditions before reserving the full two-second rekey timeout. A lifetime of two seconds or less is invalid.

Before sending an application frame, the sender **MUST** check its frame and ciphertext byte counts including the proposed frame and both reserved control frames. A frame that fits exactly may be sent. If either limit would be exceeded, the sender defers the application frame and starts or requests renewal. Both directions count every protected control and data frame against the epoch whose keys protect it. Time-based renewal **MUST** start early enough to finish within the epoch lifetime.

When renewal becomes due locally, the endpoint **MUST** pause application-data transmission. Section 9.3 defines which old-epoch data it can still receive and when it may resume sending. A failure, timeout, or inability to reserve the remaining control traffic within the epoch limits is fatal.

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

All controls are carried in `rekey` frames protected by `COSE_Encrypt0`. For a renewal starting in epoch `E`, every control carries `next_epoch = E + 1`. All controls except `rekey_ack` carry outer `epoch = E` and use epoch `E` keys. The acknowledgement carries outer `epoch = E + 1` and uses epoch `E + 1` keys.

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

TCP orders frames independently in each direction. An endpoint **MUST** pause new application sends when it starts or requests renewal, or when it receives the peer's first authenticated rekey control. Any old-epoch data already being written **MUST** precede the sender's first rekey control on the stream. The receiver uses the following controls to determine where old-epoch application data ends:

| Sender | First control after its last old-epoch `data` frame |
| --- | --- |
| Initiator | `rekey_msg1` |
| Responder | `rekey_request` if sent, otherwise `rekey_msg2` |

Until it authenticates that control from the peer, the receiver **MUST** continue reading and processing valid old-epoch `data` in order, even while waiting for a rekey reply. Each frame remains subject to the usual authentication, index, authorization, and epoch limits. Processing it does not restart the rekey timeout. After the control, any further old-epoch `data` from that peer is connection-fatal. These rules also apply when `rekey_request` and `rekey_msg1` cross.

During rekey, each endpoint **MUST** verify that the peer authenticated with the exact pinned credential used in the initial handshake and that the pin is still trusted when installing the new channel (Section 10). The responder authenticates EDHOC message 3, derives and installs the new channel, then sends `rekey_ack` under the new keys. The initiator prepares a pending channel before sending message 3 but **MUST NOT** install it or resume application traffic until it authenticates the acknowledgement under the pending new keys.

The responder may resume application sends after sending `rekey_ack`. While sends are paused, each endpoint **MUST** defer outgoing RSMP messages, including any `MessageAck` or `MessageNotAck` owed for accepted frames, and continue processing rekey controls. On successful renewal it sends the deferred messages in order under the new keys. RSMP acknowledgements retain their original `oMId`.

The session id and authorization context remain unchanged. The `rekey_ack` consumes responder-to-initiator index 1 in epoch `E + 1`, including one frame and its ciphertext bytes against that direction's new limits. The initiator **MUST** preserve that receive state when it installs the pending channel. The next responder frame uses index 2. The first initiator frame uses index 1. The previous channel's traffic secret, directional keys, and nonce prefixes **MUST** be erased after successful installation.

Rekey **MUST** complete within two seconds. A party that can still authenticate a control failure **SHOULD** send exactly one `rekey_error` with code `failed`; both parties then close the connection. Detailed cryptographic errors **MUST NOT** be exposed on the wire.

Unsolicited responses, wrong roles, wrong epochs, new-epoch data before `rekey_ack`, a `rekey_ack` under old keys, changed peer identity, or malformed controls are fatal.

## 10. Failure handling and operations

All security failures are connection-fatal. Implementations **MUST NOT** continue with degraded security, retry the connection as plaintext, skip a failed authorization check, reuse an epoch or frame index, or retain a partially established channel.

Long-term private keys, EDHOC session secrets, exporter results, traffic secrets, directional keys, and nonce prefixes **SHOULD** be erased as soon as they are no longer required. Implementations **SHOULD** use operating-system protections, restrictive file permissions, or hardware-backed key storage appropriate to the deployment.

Operational logs **SHOULD** record successful and failed authentication, authorization, rekey, credential selection, epoch changes, and reason categories. Logs **MUST NOT** contain private keys, traffic secrets, decrypted RSMP payloads unless explicitly required by policy, or peer-visible cryptographic diagnostics that create an oracle. Implementations **SHOULD** rate-limit repeated failed connection attempts.

Credential provisioning, replacement, revocation, backup, and recovery are administrative responsibilities. Each new connection **MUST** use the current local trust and authorization policy.

Revocation takes effect at an endpoint when it applies a local trust update that removes or revokes the peer's pin. As part of that update, the endpoint **MUST** close every connection authenticated with that credential, including idle connections, and abort any pending handshake or rekey using it. From that point the endpoint **MUST NOT** send or dispatch further RSMP messages on those connections, including queued messages. A concurrent handshake or rekey **MUST NOT** install a channel using the revoked credential.

A replacement credential requires a new TCP connection and initial EDHOC exchange, even when it has the same subject as the revoked credential.

## 11. Conformance requirements

A conforming implementation **MUST** test at least:

- exact deterministic-CBOR encoding and rejection of non-deterministic encodings and duplicate, missing, or unknown fields in closed security maps;
- initial handshake framing at the 65,536-byte boundary, including rejection of a declared length of 65,537 from the prefix alone;
- after each role's initial handshake completion, application of local receive limits to protected frames, including during the `Version` exchange and rekey. Where local limits permit, a valid protected frame larger than 65,536 bytes must pass the size check;
- exact CCS shape, derived KID, key lengths, private/public match, duplicate subject, duplicate KID, and unknown peer rejection;
- closure of all active and idle connections using a locally revoked pin, with no queued RSMP message sent or dispatched on them after the update;
- revocation during initial EDHOC and during rekey while `rekey_ack` is pending, including rejection of a late completion using the revoked credential;
- rejection of a new connection using the revoked pin and successful authentication on a new connection using an authorized replacement with the same subject;
- message 1 beginning with `00 04` for initial establishment and rekey, rejection of singleton arrays in either field, EAD rejection, and fresh connection identifiers;
- responder completion only after successfully sending message 4 and initiator completion only after verifying it, including a failed send and a failed verification;
- silent closure on invalid wrappers and received errors, and the Section 6.1 error code and information for a wrong suite, an unknown KID, and a malformed embedded message, with no fallback;
- exporter context identity ordering and all six outputs of the Section 7 key schedule test vector;
- known-answer encryption/decryption, directional key separation, nonce construction, AAD binding, tag failure, replay, gaps, reordering, and index exhaustion;
- byte-for-byte encoding and decoding of the Section 8.1 examples, both integer range endpoints, shortest float widths, signed zero, nested objects and arrays, and unchanged timestamp, base64, and legacy strings;
- outbound rejection of out-of-range integers, floating-point overflow or underflow to zero, and duplicate JSON names after escape decoding, with no frame sent or index consumed;
- connection closure on invalid authenticated payloads, including nested duplicate or non-text keys, tags, byte strings, non-finite floats, non-minimal encodings, and trailing items;
- continued use of the same secure channel after a post-authorization RSMP field-type failure requiring `MessageNotAck`, including delivery of the next valid message;
- one protected `Version` request and one response, each acknowledged by `oMId`, for both site-opened and supervisor-opened TCP connections and for follower/leader startup;
- selected-Core validation of both `Version` messages, including the expected `step` in Core 3.3.0 and role-based identification in supported earlier versions without `step`;
- outgoing rejection of a different locally pinned peer, listener selection by authenticated credential, and enforcement of the configured application role and permitted Core versions;
- acceptance of a single matching site ID in a site or follower request, rejection of missing, mismatched, or multiple IDs, and rejection of a legacy response whose sole site ID differs from the original request;
- authorization of the configured supervisor or leader when a valid Core 3.3.0 `supervisorId` differs from its policy identity, rejection of a missing required `supervisorId`, and authorization of a legacy responder from its pin when Core supplies no responder identity;
- authorization of identity, role, and Core version at each endpoint, including that an acknowledgement alone cannot complete authorization and that other RSMP traffic is gated until local completion;
- connection closure on a mismatched acknowledgement, a `MessageNotAck` for either `Version`, a repeated request or response, a wrong-role `Version`, or an attempt to change the authorization context;
- initiator- and responder-triggered rekey, simultaneous triggers, fresh keys, stable session id, changed-identity rejection, new-key acknowledgement, old-key erasure, and all three mandatory limits;
- consecutive responder-requested renewals at the four-frame minimum, with application data in both directions between renewals, both acknowledgement epoch fields equal to the target epoch, and subsequent responder and initiator indices 2 and 1 respectively;
- acceptance at the exact byte budget, deferral when a proposed send exceeds the remaining budget by one byte, and configuration rejection when the frame, byte, or lifetime budget leaves insufficient room for application traffic and renewal;
- delivery of in-flight old-epoch data before the peer's first rekey control for either trigger and for crossing triggers, including deferral of an owed RSMP acknowledgement until the new epoch;
- rejection of old-epoch data after each direction's first rekey control and new-epoch data before `rekey_ack`, with ordering, epoch limits, and the rekey timeout enforced throughout;
- rekey timeout, error control, invalid role, wrong epoch, unsolicited response, and old-key acknowledgement; and
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
