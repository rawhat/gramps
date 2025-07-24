# Unreleased

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
