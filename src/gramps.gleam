import gleam/bit_array
import gleam/bytes_builder.{type BytesBuilder}
import gleam/crypto
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

pub type DataFrame {
  TextFrame(payload_length: Int, payload: BitArray)
  BinaryFrame(payload_length: Int, payload: BitArray)
}

pub type ControlFrame {
  CloseFrame(payload_length: Int, payload: BitArray)
  PingFrame(payload_length: Int, payload: BitArray)
  PongFrame(payload_length: Int, payload: BitArray)
}

pub type Frame {
  Data(DataFrame)
  Control(ControlFrame)
  Continuation(length: Int, payload: BitArray)
}

@external(erlang, "crypto", "exor")
fn crypto_exor(a a: BitArray, b b: BitArray) -> BitArray

fn unmask_data(
  data: BitArray,
  masks: List(BitArray),
  index: Int,
  resp: BitArray,
) -> BitArray {
  case data {
    <<masked:bits-size(8), rest:bits>> -> {
      let assert Ok(mask_value) = list.at(masks, index % 4)
      let unmasked = crypto_exor(mask_value, masked)
      unmask_data(rest, masks, index + 1, <<resp:bits, unmasked:bits>>)
    }
    _ -> resp
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

pub fn frame_from_message(
  message: BitArray,
) -> Result(#(ParsedFrame, BitArray), FrameParseError) {
  case message {
    <<
      complete:1,
      _reserved:3,
      opcode:int-size(4),
      mask:1,
      payload_length:int-size(7),
      rest:bits,
    >> -> {
      let payload_size = case payload_length {
        126 -> 16
        127 -> 64
        _ -> 0
      }
      let masked = case mask {
        1 -> True
        0 -> False
        _ -> panic as "Somehow a bit wasn't 0 or 1"
      }
      case masked, rest {
        True, <<
          length:int-size(payload_size),
          mask1:bytes-size(1),
          mask2:bytes-size(1),
          mask3:bytes-size(1),
          mask4:bytes-size(1),
          rest:bits,
        >> -> {
          let payload_byte_size = case length {
            0 -> payload_length
            n -> n
          }
          case rest {
            <<payload:bytes-size(payload_byte_size), rest:bits>> -> {
              let data =
                unmask_data(payload, [mask1, mask2, mask3, mask4], 0, <<>>)
              case opcode {
                0 -> Ok(Continuation(payload_length, data))
                1 -> Ok(Data(TextFrame(payload_length, data)))
                2 -> Ok(Data(BinaryFrame(payload_length, data)))
                8 -> Ok(Control(CloseFrame(payload_length, data)))
                9 -> Ok(Control(PingFrame(payload_length, data)))
                10 -> Ok(Control(PongFrame(payload_length, data)))
                _ -> Error(InvalidFrame)
              }
              |> result.then(fn(frame) {
                case complete {
                  1 -> Ok(#(Complete(frame), rest))
                  0 -> Ok(#(Incomplete(frame), rest))
                  _ -> Error(InvalidFrame)
                }
              })
            }
            _ -> {
              Error(NeedMoreData(message))
              // let assert Ok(data) =
              //   transport.receive(conn.transport, conn.socket, 0)
              // frame_from_message(<<message:bits, data:bits>>, conn)
            }
          }
        }
        False, <<length:int-size(payload_size), rest:bits>> -> {
          let payload_byte_size = case length {
            0 -> payload_length
            n -> n
          }
          case rest {
            <<payload:bytes-size(payload_byte_size), rest:bits>> -> {
              case opcode {
                0 -> Ok(Continuation(payload_length, payload))
                1 -> Ok(Data(TextFrame(payload_length, payload)))
                2 -> Ok(Data(BinaryFrame(payload_length, payload)))
                8 -> Ok(Control(CloseFrame(payload_length, payload)))
                9 -> Ok(Control(PingFrame(payload_length, payload)))
                10 -> Ok(Control(PongFrame(payload_length, payload)))
                _ -> Error(InvalidFrame)
              }
              |> result.then(fn(frame) {
                case complete {
                  1 -> Ok(#(Complete(frame), rest))
                  0 -> Ok(#(Incomplete(frame), rest))
                  _ -> Error(InvalidFrame)
                }
              })
            }
            _ -> {
              Error(NeedMoreData(message))
            }
          }
        }
        _, _ -> {
          Error(InvalidFrame)
        }
      }
    }
    _ -> {
      Error(InvalidFrame)
    }
  }
}

pub fn frame_to_bytes_builder(
  frame: Frame,
  mask: Option(BitArray),
) -> BytesBuilder {
  case frame {
    Data(TextFrame(payload_length, payload)) ->
      make_frame(1, payload_length, payload, mask)
    Control(CloseFrame(payload_length, payload)) ->
      make_frame(8, payload_length, payload, mask)
    Data(BinaryFrame(payload_length, payload)) ->
      make_frame(2, payload_length, payload, mask)
    Control(PongFrame(payload_length, payload)) ->
      make_frame(10, payload_length, payload, mask)
    Control(PingFrame(payload_length, payload)) ->
      make_frame(9, payload_length, payload, mask)
    Continuation(length, payload) -> make_frame(0, length, payload, mask)
  }
}

fn make_frame(
  opcode: Int,
  length: Int,
  payload: BitArray,
  mask: Option(BitArray),
) -> BytesBuilder {
  let length_section = case length {
    length if length > 65_535 -> <<127:7, length:int-size(64)>>
    length if length >= 126 -> <<126:7, length:int-size(16)>>
    _length -> <<length:7>>
  }

  let masked = case option.is_some(mask) {
    True -> 1
    False -> 0
  }

  let mask_key = option.unwrap(mask, <<>>)

  <<
    1:1,
    0:3,
    opcode:4,
    masked:1,
    length_section:bits,
    mask_key:bits,
    payload:bits,
  >>
  |> bytes_builder.from_bit_array
}

pub fn to_text_frame(data: String, mask: Bool) -> BytesBuilder {
  let msg = bit_array.from_string(data)
  let size = bit_array.byte_size(msg)
  let #(maybe_masked_data, mask) = case mask {
    True -> {
      let mask = crypto.strong_random_bytes(4)
      let assert <<
        mask1:bytes-size(1),
        mask2:bytes-size(1),
        mask3:bytes-size(1),
        mask4:bytes-size(1),
      >> = mask
      #(unmask_data(msg, [mask1, mask2, mask3, mask4], 0, <<>>), Some(mask))
    }
    _ -> #(msg, None)
  }
  frame_to_bytes_builder(Data(TextFrame(size, maybe_masked_data)), mask)
}

pub fn to_binary_frame(data: BitArray, mask: Bool) -> BytesBuilder {
  let size = bit_array.byte_size(data)
  let #(maybe_masked_data, mask) = case mask {
    True -> {
      let mask = crypto.strong_random_bytes(4)
      let assert <<
        mask1:bytes-size(1),
        mask2:bytes-size(1),
        mask3:bytes-size(1),
        mask4:bytes-size(1),
      >> = mask
      #(unmask_data(data, [mask1, mask2, mask3, mask4], 0, <<>>), Some(mask))
    }
    _ -> #(data, None)
  }
  frame_to_bytes_builder(Data(BinaryFrame(size, maybe_masked_data)), mask)
}

const websocket_key = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

pub const websocket_client_key = "dGhlIHNhbXBsZSBub25jZQ=="

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
