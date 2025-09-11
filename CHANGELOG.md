# Unreleased

- Add strict WebSocket protocol compliance validation
- Add control frame fragmentation validation; control frames must not be fragmented
- Add close frame validation; validate close codes and UTF-8 payload
- Add `decode_many_frames_result` function with proper error propagation
- Fix partial frame handling for TCP fragmentation; incomplete frames return `NeedMoreData` instead of `InvalidFrame`  
- Fix masked frame parsing for incomplete frames
- Add UTF-8 validation for complete text frames and assembled fragmented messages
- Extract RSV bits in frame header parsing instead of ignoring as reserved field
- Optimize data unmasking performance by replacing recursive byte-by-byte XOR with a bulk XOR operation using a repeating mask key
- Defer decompression to the aggregation phase to correctly handle fragmented compressed messages per the permessage-deflate extension, instead of inflating per-frame
- Rewrite `aggregate-frames` to accumulate payloads in a list and concatenate once at the end, rather than incremential bit array appends
- Fix apply_inflate to correctly call compression.inflate instead of compression.deflate

# v6.0.0

- Refactor `websocket` module a fair bit
- Fix/support some compression flags

# v5.0.0

- Refactor some messages (mostly removing duplicate `payload_length` fields)
- Add support for exit reasons

# v4.0.0

- Remove `client_key` public variable
- Replace with `make_client_key` to properly conform to the RFC constraints

# v3.0.3

- Remove some deprecated functions

# v3.0.1

- Relaxed `gleam_http` constraint to permit v4

# v3.0.0

- Bump `stdlib` requirement to >=0.44.0

# v2.0.0

- Reorganized the modules
- Added some HTTP stuff
- Fixed some bugs with websocket stuff

# v1.1.0

- Proper HTTP request / response parsing
- Better WebSocket message aggregation
- Some actual tests!

# v1.0.0

- Initial release
- Support for rudimentary HTTP parsing / encoding
- Support for WebSocket frames (mostly)
