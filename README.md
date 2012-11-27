# Disservice

Simply record your requests to a remote webservice, then replay them later in your tests.

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
