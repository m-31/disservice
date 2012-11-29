# Disservice

Simply record your requests to a remote webservice, then replay them later in your tests. Matches request-line and headers with wildcards, rewrites host headers, and has a silly name.

Disservice is © copyright 2012 Matthias Bauer <http://matthias-bauer.net/>. Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

## Basic Usage

```
Usage: disservice [options]
        --known MODE                 What to do with 'known' (matched) requests (default: replay)
                                       pass: pass request/response unchanged
                                       replay: return stored response
        --unknown MODE               What to do with 'unknown' (unmatched) requests (default: record)
                                       pass: pass request/response unchanged
                                       record: pass request upstream and store it
                                       croak: throw an exception
    -m, --mocks DIRECTORY            Read recorded requests from DIRECTORY (default: ./mocks/)
    -l, --listen PORT                Listen on port PORT (default: 80)
    -d, --dsthost DSTHOST            Destination host to forward requests to (default: localhost)
    -p, --dstport DSTPORT            Destination port to forward requests to (default: 8080)
        --debug                      Turn on debug output
        --quiet                      Turn off info output
        --daemonize                  Run in background
    -h, --help                       Display this help.
```

## Matching

An incoming request's request-line and headers are matched against all stored requests.

### Matching example: Simple

Request:
```
GET / HTTP/1.1
Host: localhost
Accept: */*
```

Stored request:
```
GET / HTTP/1.1
```

This will (obviously) match because the stored request has no request headers and the request-line is equal.

### Matching example: Wildcard request-line

Request:
```
GET /example/article_search?shop=1&query=shoes
Host: www.example.com
Connection: Keep-Alive
User-Agent: curl
```

Stored request:
```
GET /example/article_search?shop=1&query=* HTTP/1.1
Host: www.example.com
Connection: Keep-Alive
```

The stored request-line will be wildcard-matched against the client request and match successfully. Then, all header lines sent by the client are matched against the stored header lines:

1. If the same header is in the client request and the stored request, that header is wildcard matched
2. If the client sends a header that is not present in the stored request, that header matches
3. If the client fails to send a header that is present in the stored request, that header does not match

In this case, since the `User-Agent` header is not present in the stored request, the match is successful.

### Matching example: Mismatching headers

Request:
```
GET /example/article_search?shop=1&query=shoes
Host: www.example.com
Connection: close
```

Stored request:
```
GET /example/article_search?shop=1&query=* HTTP/1.1
Host: www.example.com
User-Agent: curl
```

This request would not match this stored request because the client did not send a matching User-Agent line.

Request:
```
GET /example/article_search?shop=1&query=shoes
Host: www.example.com
Connection: close
```

Stored request:
```
GET /example/article_search?shop=1&query=* HTTP/1.1
Host: www.example.com
Connection: Keep-Alive
```

This request would not match this stored request because the `Connection` header does not match.

## Example

You want to mock a webservice for your integration or load tests. Configure your test or server to use *disservice* as upstream. Set *disservice* to record unknown requests (this is the default).

```
./disservice.rb -l <LOCAL-PORT> -d <UPSTREAM-HOST> -p <UPSTREAM-PORT>
```

Then run your test and fill *disservice*'s request cache.

Now you can edit the stored requests and add wildcards to the HTTP request part, e.g. change the first line (request-line) of ./mocks/<FILE> to:

```
GET /assets/application.css* HTTP/1.?
```

Then, all requests that start with `/assets/application.css` will be sent the response from this file.

Restart *disservice* to make it re-read the mocks file. The next time you run your tests, all responses should come from *disservice*'s cache.
To make sure that no new requests are passed on to the upstream service, start *disservice* with `--unknown croak`:

```
./disservice.rb --unknown croak -l <LOCAL-PORT> -d <UPSTREAM-HOST> -p <UPSTREAM-PORT>
```

Now, *disservice* will fail catastrophically when it encounters a request it cannot match. Fix your request matcher, rinse, and repeat.
