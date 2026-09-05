# gramps

[![Package Version](https://img.shields.io/hexpm/v/gramps)](https://hex.pm/packages/gramps)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/gramps/)

Some helper data types and functions for WebSockets.

Used in [stratus](https://github.com/rawhat/stratus) and [mist](https://github.com/rawhat/mist) as well.

I will document this more, and am definitely open to adding / reshaping this to
fit the needs of other packages!

## Installation

```sh
gleam add gramps
```

Its documentation can be found at <https://hexdocs.pm/gramps>.

## Bounded WebSocket decoding

`gramps/websocket/decoder` provides an incremental decoder for uncompressed
messages. Configure a maximum frame payload and a maximum complete message:

```gleam
import gramps/websocket/decoder

let assert Ok(connection) =
  decoder.new(max_frame_bytes: 65_536, max_message_bytes: 262_144)
let result = decoder.next(connection, incoming_bytes)
```

`More` retains an incomplete frame. `Frame` returns one complete message or
control frame, the updated decoder, and unconsumed input. Handle that frame
before calling `next` again with the remaining input. This avoids collecting
every message in a received chunk before the application can process one.

The decoder checks declared lengths before retaining or unmasking payloads.
Fragment sizes count toward one message limit across calls; intervening control
frames do not reset that budget. It rejects compressed frames because a limit
on compressed bytes cannot bound decompressed output. These limits do not bound
the caller's input allocation, native socket buffers, connection count, or
outbound queues. Existing `websocket.decode_frame` behavior is unchanged.
