# Disservice

Simply record your requests to a remote webservice, then replay them later in your tests.

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

## Example

You want to mock a webservice for your integration or load tests. Configure your test or server to use *disservice* as upstream. Set *disservice* to record unknown requests (this is the default).

```
./disservice.rb -l <LOCAL-PORT> -d <UPSTREAM-HOST> -p <UPSTREAM-PORT>
```

Then run your test and fill *disservice*'s request cache.

Now you can edit the stored requests and add wildcards to the HTTP request-line, e.g. change the first line of ./mocks/<FILE> to:

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
