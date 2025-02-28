# Platform API authentication

The Platform API uses an authentication method based on the
[AWS v4 Signature process](https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html).

This is used for

- all Platform API calls to application endpoints, like the install/uninstall endpoints.
- calls to Platform API from external (not available currently)

## Authentication key pair

We’re using the same model that AWS uses and providing external applications with a public key and private key.
The access key and secret key in AWS terminology respectively. Each key will have a prefix that allows Help Scout to
register with GitHub a vulnerability scanner (i.e. look for private keys that are checked into repositories).

The public key prefix is `hsp_pub_`.
The private key prefix is `hsp_pri_`.

The public key includes 16 bytes of cryptographical secure random data after the prefix which will be encoded as a
hexadecimal value. For example:

```
hsp_pub_e5a3b730a586108bd1608b60e4483ade
```

16 bytes is enough uniqueness, so prevent key clashes.
When encoded as hexadecimal, that gives us 40 character long strings when including the prefix.

The private key includes 28 bytes of cryptographical secure random data after the prefix which will be encoded as a
hexadecimal value. For example:

```
hsp_pri_f56ae73ab3754d55e70f15a6ea36ed3d0b1195ad080932d8d0d474bf
```


## Quick example

```http request
POST /v1/uninstall
Host: textline.net
Content-Type: application/json; charset=utf-8
Content-Length: 294
X-HS-Platform-Request-Timestamp: 1686094663
Authorization: HSP1-HMAC-SHA256 pub=hsp_pub_1234,sig=a627dadee39529d87fc96345cce959b7b51219cb5d6c02163157ea7b006319da,headers=content-length;content-type;host;x-hs-platform-request-timestamp

    {
      "companyId": 4,
      "userId": 1,
      "installationId": 3,
    }
```

The above authorization header uses the following string to sign:

```
HSP1-HMAC-SHA256
1686094663
d5a0e12dcc48b551fe50c0574796ba43257bd74c198949e828c84f0879493079
```

Which would then be signed:

```
Hex(HMAC-SHA256(PlatformPrivateKey, 92ac4e16fc3468f36d3efc69ea6fdf9d434a21e1b99b19807aa189bc9cba2908))
```

## HTTP Pieces Used

The Authn signature is made up of the following parts of an HTTP request at a minimum:

- Method (GET, PUT, POST, etc.)
- URI (`/v1/refund` , `/v1/returns` , etc.)
- Query String (if available)
- `host` header value
- `x-hs-platform-request-timestamp` header value
- hashed request body (if available)

Following the rules below, any additional headers can be included to provide more protection against tampering. But they aren’t required. The ones above are required.


### Canonical Request

The pieces above will be assembled as follows:

```
method\n
uri\n
query-string\n
headers\n
hashed-payload
```

| Part           | Description                                                                                                                                                |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| method         | The HTTP method of the request (GET, PUT, POST, etc.)                                                                                                      |
| uri            | The URI encoded absolute path of the request not including the query string.                                                                               |
| query-string   | See below for details                                                                                                                                      |
| headers        | See below for details                                                                                                                                      |
| hashed-payload | hexadecimal value of the SHA256 hash of the request payload. Note: If there is no request payload, use an empty string for request payload before hashing. |


### URI Encoding

Due to the differences in URI encoding libraries and ambiguities in the RFC, your URI encoding function must enforce the following:

- URI encode every byte except the unreserved characters: 'A'-'Z', 'a'-'z', '0'-'9', '-', '.', '_', and '~'.
- The space character is a reserved character and must be encoded as "%20" (and not as "+").
- Each URI encoded byte is formed by a '%' and the two-digit hexadecimal value of the byte.
- Letters in the hexadecimal value must be uppercase, for example "%1A".
- Encode the forward slash character, '/', everywhere except when used as for absolute path in canonical request.
  Query String

Each name and value should be URI encoded separately and then sorted alphabetically. All key/values are then joined using an ampersand character (`&` ) as a separator.

If the parameter contains no value, use an empty string as its URI encoded value.

Given the query string:

```http request
user_id=1&company_id=4&sort=name,created_at&limit=5&activeOnly
```

It would be converted by:

```
UriEncode("activeOnly")+"="+""+"&"
UriEncode("company_id")+"="+UriEncode("4")+"&"
UriEncode("limit")+"="+UriEncode("5")+"&"
UriEncode("sort")+"="+UriEncode("name,created_at")+"&"
UriEncode("user_id")+"="+UriEncode("1")
```

Which gives:

```http request
activeOnly=&company_id=4&limit=5&sort=name%2Ccreated_at&user_id=1
```


### Headers

This is the alphabetically sorted list of lower case header names, and their values. Each is separated by a newline character (`\n` ). Using the above minimum headers, we’d have:

```
host:myhost
x-hs-platform-request-timestamp:1686094663
```


### String to Sign

Create a string by concatenating the following strings, separated by newline characters. Do not end this string with a newline character.

```
Algorithm
RequestTimestamp
HashedCanonicalRequest
```

1. Algorithm is `HSP1-HMAC-SHA256` for the first version
2. RequestTimestamp is the UNIX timestamp of when the request is being made
3. HashedCanonicalRequest is the hexadecimal value of a `SHA256` hash of the canonical request

For version 1 of the signature process, that string is signed like so:

```
Hex(HMAC-SHA256(PlatformPrivateKey, StringToSign))
```


### Passing it along

The final signature can be passed along in multiple ways. But we’ll be using the `authorization` header. It would look like this:

```
Authorization: HSP1-HMAC-SHA256 pub={platform_public_key},sig={calculate_signature},headers={headers_in_signature}
```