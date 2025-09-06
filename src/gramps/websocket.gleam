import gleam/bit_array
import gleam/bool
import gleam/bytes_tree.{type BytesTree}
import gleam/crypto
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gramps/websocket/compression.{
  type Context, type ContextTakeover, ContextTakeover,
}

pub type DataFrame {
  TextFrame(payload: BitArray)
  BinaryFrame(payload: BitArray)

  CompressedTextFrame(payload: BitArray)
  CompressedBinaryFrame(payload: BitArray)
}

pub type CloseReason {
  NotProvided
  Normal(body: BitArray)
  GoingAway(body: BitArray)
  ProtocolError(body: BitArray)
  UnexpectedDataType(body: BitArray)
  InconsistentDataType(body: BitArray)
  PolicyViolation(body: BitArray)
  MessageTooBig(body: BitArray)
  MissingExtensions(body: BitArray)
  UnexpectedCondition(body: BitArray)
  /// Usually used for `4000` codes.
  CustomCloseReason(
    /// If `code >= 5000`, it will be the same as a `Normal` close reason.
    code: Int,
    body: BitArray,
  )
}

pub type ControlFrame {
  CloseFrame(reason: CloseReason)
  PingFrame(payload: BitArray)
  PongFrame(payload: BitArray)
}

pub type Frame {
  Data(DataFrame)
  Control(ControlFrame)
  Continuation(length: Int, payload: BitArray)
}

@external(erlang, "crypto", "exor")
fn crypto_exor(a a: BitArray, b b: BitArray) -> BitArray

fn mask_data(data: BitArray, masks: List(BitArray)) -> BitArray {
  let assert [m1, m2, m3, m4] = masks
  let mask_key = <<m1:bits, m2:bits, m3:bits, m4:bits>>

  let payload_size = bit_array.byte_size(data)
  let full_mask = create_repeating_mask(mask_key, payload_size)
  crypto_exor(data, full_mask)
}

fn create_repeating_mask(mask_key: BitArray, size: Int) -> BitArray {
  case size {
    1 | 2 | 3 | 4 -> bit_array.slice(mask_key, 0, size) |> result.unwrap(<<>>)

    _ -> {
      let repetitions = size / 4
      let remainder = size % 4
      let base = list.repeat(mask_key, repetitions) |> bit_array.concat

      case remainder {
        0 -> base
        n -> {
          let partial = bit_array.slice(mask_key, 0, n) |> result.unwrap(<<>>)
          <<base:bits, partial:bits>>
        }
      }
    }
  }
}

pub type FrameParseError {
  NeedMoreData(BitArray)
  InvalidFrame
}

pub type ParsedFrame {
  Complete(Frame)
  Incomplete(Frame)
}

pub fn decode_frame(
  message: BitArray,
  context: Option(Context),
) -> Result(#(ParsedFrame, BitArray), FrameParseError) {
  case message {
    <<
      complete:1,
      compressed:1,
      rsv2:1,
      rsv3:1,
      opcode:int-size(4),
      masked:1,
      payload_length:int-size(7),
      rest:bits,
    >> -> {
      let compressed = compressed == 1
      let masked = masked == 1

      use <- bool.guard(
        when: compressed && option.is_none(context),
        return: Error(InvalidFrame),
      )

      use <- bool.guard(rsv2 == 1 || rsv3 == 1, return: Error(InvalidFrame))

      use <- bool.guard(
        when: {
          let is_control_frame = opcode >= 8 && opcode <= 10
          let is_fragmented = complete == 0
          is_control_frame && is_fragmented
        },
        return: Error(InvalidFrame),
      )

      let payload_size = case payload_length {
        126 -> 16
        127 -> 64
        _ -> 0
      }

      let maybe_pair = case masked, rest {
        True,
          <<
            length:int-size(payload_size),
            mask1:bytes-size(1),
            mask2:bytes-size(1),
            mask3:bytes-size(1),
            mask4:bytes-size(1),
            rest:bits,
          >>
        -> {
          let payload_byte_size = case length {
            0 -> payload_length
            n -> n
          }

          case bit_array.byte_size(rest) >= payload_byte_size, rest {
            True, <<payload:bytes-size(payload_byte_size), remaining:bits>> -> {
              let data = mask_data(payload, [mask1, mask2, mask3, mask4])
              Ok(#(data, remaining))
            }
            _, _ -> Error(NeedMoreData(message))
          }
        }
        True, _rest -> Error(NeedMoreData(message))
        False, <<length:int-size(payload_size), rest:bits>> -> {
          let payload_byte_size = case length {
            0 -> payload_length
            n -> n
          }
          case rest {
            <<payload:bytes-size(payload_byte_size), rest:bits>> -> {
              Ok(#(payload, rest))
            }
            _ -> {
              Error(NeedMoreData(message))
            }
          }
        }
        _, _ -> Error(InvalidFrame)
      }

      use #(data, rest) <- result.try(maybe_pair)
      case opcode {
        0 -> Ok(Continuation(payload_size, data))
        1 -> {
          case complete == 1, compressed {
            True, True -> Ok(Data(CompressedTextFrame(data)))
            True, False -> Ok(Data(TextFrame(data)))
            False, True -> Ok(Data(CompressedTextFrame(data)))
            False, False -> Ok(Data(TextFrame(data)))
          }
        }
        2 -> {
          case compressed {
            True -> Ok(Data(CompressedBinaryFrame(data)))
            False -> Ok(Data(BinaryFrame(data)))
          }
        }
        8 -> {
          case data {
            <<>> -> Ok(Control(CloseFrame(NotProvided)))
            <<code:16, rest:bits>> -> {
              case is_valid_close_code(code), bit_array.is_utf8(rest) {
                True, True -> {
                  case code {
                    1000 -> Ok(Control(CloseFrame(Normal(rest))))
                    1001 -> Ok(Control(CloseFrame(GoingAway(rest))))
                    1002 -> Ok(Control(CloseFrame(ProtocolError(rest))))
                    1003 -> Ok(Control(CloseFrame(UnexpectedDataType(rest))))
                    1007 -> Ok(Control(CloseFrame(InconsistentDataType(rest))))
                    1008 -> Ok(Control(CloseFrame(PolicyViolation(rest))))
                    1009 -> Ok(Control(CloseFrame(MessageTooBig(rest))))
                    1010 -> Ok(Control(CloseFrame(MissingExtensions(rest))))
                    1011 -> Ok(Control(CloseFrame(UnexpectedCondition(rest))))
                    _ -> Ok(Control(CloseFrame(CustomCloseReason(code, rest))))
                  }
                }
                _, _ -> Error(InvalidFrame)
              }
            }
            _ -> Error(InvalidFrame)
          }
        }
        9 -> Ok(Control(PingFrame(data)))
        10 -> Ok(Control(PongFrame(data)))
        _ -> Error(InvalidFrame)
      }
      |> result.try(fn(frame) {
        case complete {
          1 -> Ok(#(Complete(frame), rest))
          0 -> Ok(#(Incomplete(frame), rest))
          _ -> Error(InvalidFrame)
        }
      })
    }
    _ -> Error(NeedMoreData(message))
  }
}

fn is_valid_close_code(code: Int) -> Bool {
  case code {
    1000 | 1001 | 1002 | 1003 | 1007 | 1008 | 1009 | 1010 | 1011 -> True
    code if code >= 3000 && code <= 4999 -> True
    _ -> False
  }
}

pub fn encode_text_frame(
  data: String,
  context: Option(Context),
  mask: Option(BitArray),
) -> BytesTree {
  to_frame(bit_array.from_string(data), context, mask, TextFrame, Data)
}

pub fn encode_binary_frame(
  data: BitArray,
  context: Option(Context),
  mask: Option(BitArray),
) -> BytesTree {
  to_frame(data, context, mask, BinaryFrame, Data)
}

pub fn encode_close_frame(
  reason: CloseReason,
  mask: Option(BitArray),
) -> BytesTree {
  encode_frame(Control(CloseFrame(reason)), Uncompressed, mask)
}

pub fn encode_ping_frame(data: BitArray, mask: Option(BitArray)) -> BytesTree {
  to_frame(data, None, mask, PingFrame, Control)
}

pub fn encode_pong_frame(data: BitArray, mask: Option(BitArray)) -> BytesTree {
  to_frame(data, None, mask, PongFrame, Control)
}

pub fn encode_continuation_frame(
  data: BitArray,
  total_size: Int,
  mask: Option(BitArray),
) -> BytesTree {
  let payload = apply_mask(data, mask)
  encode_frame(Continuation(total_size, payload), Uncompressed, mask)
}

fn encode_frame(
  frame: Frame,
  compressed: Compression,
  mask: Option(BitArray),
) -> BytesTree {
  case frame {
    Data(TextFrame(payload)) -> {
      let payload_length = bit_array.byte_size(payload)
      make_frame(1, payload_length, payload, compressed, mask)
    }

    Data(CompressedTextFrame(_)) ->
      panic as "CompressedTextFrame should not be used by user"
    Data(CompressedBinaryFrame(_)) ->
      panic as "CompressedBinaryFrame should not be used by user"

    Control(CloseFrame(reason)) -> {
      let #(payload_length, payload) = case reason {
        NotProvided -> #(0, <<>>)
        GoingAway(body:) -> {
          let payload_size = bit_array.byte_size(body) + 2
          #(payload_size, <<1001:16, body:bits>>)
        }
        InconsistentDataType(body:) -> {
          let payload_size = bit_array.byte_size(body) + 2
          #(payload_size, <<1007:16, body:bits>>)
        }
        MessageTooBig(body:) -> {
          let payload_size = bit_array.byte_size(body) + 2
          #(payload_size, <<1009:16, body:bits>>)
        }
        MissingExtensions(body:) -> {
          let payload_size = bit_array.byte_size(body) + 2
          #(payload_size, <<1010:16, body:bits>>)
        }
        Normal(body:) -> {
          let payload_size = bit_array.byte_size(body) + 2
          #(payload_size, <<1000:16, body:bits>>)
        }
        PolicyViolation(body:) -> {
          let payload_size = bit_array.byte_size(body) + 2
          #(payload_size, <<1008:16, body:bits>>)
        }
        ProtocolError(body:) -> {
          let payload_size = bit_array.byte_size(body) + 2
          #(payload_size, <<1002:16, body:bits>>)
        }
        UnexpectedCondition(body:) -> {
          let payload_size = bit_array.byte_size(body) + 2
          #(payload_size, <<1011:16, body:bits>>)
        }
        UnexpectedDataType(body:) -> {
          let payload_size = bit_array.byte_size(body) + 2
          #(payload_size, <<1003:16, body:bits>>)
        }
        CustomCloseReason(code:, body:) -> {
          let payload_size = bit_array.byte_size(body) + 2
          // Prevents integer overflow and changes the status code to `Normal` for invalid codes.
          let code = case code < 5000 {
            True -> code
            False -> 1000
          }
          #(payload_size, <<code:16, body:bits>>)
        }
      }
      make_frame(8, payload_length, apply_mask(payload, mask), compressed, mask)
    }
    Data(BinaryFrame(payload)) -> {
      let payload_length = bit_array.byte_size(payload)
      make_frame(2, payload_length, payload, compressed, mask)
    }
    Control(PongFrame(payload)) -> {
      let payload_length = bit_array.byte_size(payload)
      make_frame(10, payload_length, payload, compressed, mask)
    }
    Control(PingFrame(payload)) -> {
      let payload_length = bit_array.byte_size(payload)
      make_frame(9, payload_length, payload, compressed, mask)
    }
    Continuation(length, payload) ->
      make_frame(0, length, payload, compressed, mask)
  }
}

fn make_length(length: Int) -> BitArray {
  case length {
    length if length > 65_535 -> <<127:7, length:int-size(64)>>
    length if length >= 126 -> <<126:7, length:int-size(16)>>
    _length -> <<length:7>>
  }
}

type Compression {
  Compressed
  Uncompressed
}

fn make_frame(
  opcode: Int,
  length: Int,
  payload: BitArray,
  compressed: Compression,
  mask: Option(BitArray),
) -> BytesTree {
  let length_section = make_length(length)

  let masked = case option.is_some(mask) {
    True -> 1
    False -> 0
  }

  let mask_key = option.unwrap(mask, <<>>)

  let compressed = case compressed {
    Compressed -> 1
    Uncompressed -> 0
  }

  <<
    1:1,
    compressed:1,
    0:2,
    opcode:4,
    masked:1,
    length_section:bits,
    mask_key:bits,
    payload:bits,
  >>
  |> bytes_tree.from_bit_array
}

pub fn apply_mask(data: BitArray, mask: Option(BitArray)) -> BitArray {
  case mask {
    Some(mask) -> {
      let assert <<
        mask1:bytes-size(1),
        mask2:bytes-size(1),
        mask3:bytes-size(1),
        mask4:bytes-size(1),
      >> = mask
      mask_data(data, [mask1, mask2, mask3, mask4])
    }
    None -> data
  }
}

pub fn apply_deflate(data: BitArray, context: Option(Context)) -> BitArray {
  case context {
    Some(context) -> compression.deflate(context, data)
    _ -> data
  }
}

pub fn apply_inflate(data: BitArray, context: Option(Context)) -> BitArray {
  case context {
    Some(context) -> compression.inflate(context, data)
    _ -> data
  }
}

fn to_frame(
  data: BitArray,
  context: Option(Context),
  mask: Option(BitArray),
  create_inner_frame: fn(BitArray) -> a,
  create_frame: fn(a) -> Frame,
) -> BytesTree {
  let frame =
    data
    |> apply_deflate(context)
    |> apply_mask(mask)
    |> create_inner_frame
    |> create_frame
  let compress = case context {
    Some(_context) -> Compressed
    _ -> Uncompressed
  }
  encode_frame(frame, compress, mask)
}

pub fn decode_many_frames(
  data: BitArray,
  context: Option(Context),
  frames: List(ParsedFrame),
) -> #(List(ParsedFrame), BitArray) {
  case decode_frame(data, context) {
    Ok(#(frame, <<>>)) -> #(list.reverse([frame, ..frames]), <<>>)
    Ok(#(frame, rest)) -> decode_many_frames(rest, context, [frame, ..frames])
    Error(NeedMoreData(rest)) -> #(list.reverse(frames), rest)
    Error(InvalidFrame) -> #(list.reverse(frames), data)
  }
}

pub type ManyFramesParseError {
  NeedMoreDataAccumulated(parsed: List(ParsedFrame), rest: BitArray)
  ContainsInvalidFrame
}

pub fn decode_many_frames_result(
  data: BitArray,
  context: Option(Context),
  frames: List(ParsedFrame),
) -> Result(#(List(ParsedFrame), BitArray), ManyFramesParseError) {
  case decode_frame(data, context) {
    Ok(#(frame, <<>>)) -> Ok(#(list.reverse([frame, ..frames]), <<>>))
    Ok(#(frame, rest)) ->
      decode_many_frames_result(rest, context, [frame, ..frames])
    Error(NeedMoreData(rest)) ->
      Error(NeedMoreDataAccumulated(list.reverse(frames), rest))
    Error(InvalidFrame) -> Error(ContainsInvalidFrame)
  }
}

pub fn aggregate_frames(
  frames: List(ParsedFrame),
  accumulated: Option(#(Frame, List(BitArray))),
  joined: List(Frame),
  context: Option(Context),
) -> Result(List(Frame), Nil) {
  case frames, accumulated {
    // No more frames - we are done
    [], _ -> Ok(list.reverse(joined))

    // Complete standalone frame
    [Complete(frame), ..rest], None -> {
      case frame {
        Data(CompressedTextFrame(data)) -> {
          // Complete compressed frame - decompress it
          case context {
            Some(ctx) -> {
              let decompressed = compression.inflate(ctx, data)
              case bit_array.is_utf8(decompressed) {
                True -> {
                  let final_frame = Data(TextFrame(decompressed))
                  aggregate_frames(rest, None, [final_frame, ..joined], context)
                }
                False -> Error(Nil)
              }
            }
            None -> Error(Nil)
          }
        }
        Data(CompressedBinaryFrame(data)) -> {
          case context {
            Some(ctx) -> {
              let decompressed = compression.inflate(ctx, data)
              let final_frame = Data(BinaryFrame(decompressed))
              aggregate_frames(rest, None, [final_frame, ..joined], context)
            }
            None -> Error(Nil)
          }
        }
        Data(TextFrame(data)) -> {
          case bit_array.is_utf8(data) {
            True -> aggregate_frames(rest, None, [frame, ..joined], context)
            False -> Error(Nil)
          }
        }
        Data(BinaryFrame(_)) ->
          aggregate_frames(rest, None, [frame, ..joined], context)
        Control(_) -> aggregate_frames(rest, None, [frame, ..joined], context)
        Continuation(..) -> Error(Nil)
      }
    }

    // Incomplete frame starting fragmentation
    [Incomplete(frame), ..rest], None -> {
      let initial_payload = case frame {
        Data(TextFrame(payload)) -> payload
        Data(BinaryFrame(payload)) -> payload
        Data(CompressedTextFrame(payload)) -> payload
        Data(CompressedBinaryFrame(payload)) -> payload
        Continuation(_, payload) -> payload
        Control(_) -> <<>>
      }
      aggregate_frames(rest, Some(#(frame, [initial_payload])), joined, context)
    }

    // Complete continuation; finish fragmented message
    [Complete(Continuation(payload: data, ..)), ..rest],
      Some(#(initial_frame, payloads))
    -> {
      let all_payloads = [data, ..payloads] |> list.reverse()
      let final_payload = bit_array.concat(all_payloads)

      case initial_frame {
        Data(CompressedTextFrame(_)) -> {
          case context {
            Some(ctx) -> {
              let decompressed = compression.inflate(ctx, final_payload)
              case bit_array.is_utf8(decompressed) {
                True -> {
                  let final_frame = Data(TextFrame(decompressed))
                  aggregate_frames(rest, None, [final_frame, ..joined], context)
                }
                False -> Error(Nil)
              }
            }
            None -> Error(Nil)
          }
        }
        Data(CompressedBinaryFrame(_)) -> {
          case context {
            Some(ctx) -> {
              let decompressed = compression.inflate(ctx, final_payload)
              let final_frame = Data(BinaryFrame(decompressed))
              aggregate_frames(rest, None, [final_frame, ..joined], context)
            }
            None -> Error(Nil)
          }
        }
        Data(TextFrame(_)) -> {
          case bit_array.is_utf8(final_payload) {
            True -> {
              let final_frame = Data(TextFrame(final_payload))
              aggregate_frames(rest, None, [final_frame, ..joined], context)
            }
            False -> Error(Nil)
          }
        }
        Data(BinaryFrame(_)) -> {
          let final_frame = Data(BinaryFrame(final_payload))
          aggregate_frames(rest, None, [final_frame, ..joined], context)
        }
        Control(_) -> Error(Nil)
        Continuation(..) -> Error(Nil)
      }
    }

    // Incomplete continuation; keep building the message
    [Incomplete(Continuation(payload: data, ..)), ..rest],
      Some(#(initial_frame, payloads))
    -> {
      aggregate_frames(
        rest,
        Some(#(initial_frame, [data, ..payloads])),
        joined,
        context,
      )
    }

    _, _ -> Error(Nil)
  }
}

const websocket_key = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

pub fn make_client_key() -> String {
  let bytes = crypto.strong_random_bytes(16)
  bit_array.base64_encode(bytes, True)
}

type ShaHash {
  Sha
}

pub fn parse_websocket_key(key: String) -> String {
  key
  |> string.append(websocket_key)
  |> crypto_hash(Sha, _)
  |> base64_encode
}

@external(erlang, "crypto", "hash")
fn crypto_hash(hash hash: ShaHash, data data: String) -> String

@external(erlang, "base64", "encode")
fn base64_encode(data data: String) -> String

pub fn has_deflate(extensions: List(String)) -> Bool {
  list.any(extensions, fn(str) { str == "permessage-deflate" })
}

pub fn get_context_takeovers(extensions: List(String)) -> ContextTakeover {
  let no_client_context_takeover =
    list.any(extensions, fn(str) { str == "client_no_context_takeover" })
  let no_server_context_takeover =
    list.any(extensions, fn(str) { str == "server_no_context_takeover" })
  ContextTakeover(
    no_client: no_client_context_takeover,
    no_server: no_server_context_takeover,
  )
}
