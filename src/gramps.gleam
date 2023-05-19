import gleam/base
import gleam/bit_builder.{BitBuilder}
import gleam/bit_string
import gleam/list
import gleam/string

pub type FrameType {
  Close
  Text
  Binary
  Ping
  Pong
}

// TODO:  support more

// TODO:  probably will need to support flags
pub type Frame {
  Incomplete(
    frame_type: FrameType,
    length: Int,
    mask: List(BitString),
    payload: BitString,
    remaining: Int,
  )
  CloseFrame(payload: BitString)
  TextFrame(payload: BitString)
  BinaryFrame(payload: BitString)
  PingFrame
  PongFrame
}

fn unmask_data(
  data: BitString,
  masks: List(BitString),
  index: Int,
  resp: BitString,
) -> BitString {
  case data {
    <<>> -> resp
    <<masked:bit_string-size(8), rest:bit_string>> -> {
      let assert Ok(mask_value) = list.at(masks, index % 4)
      let unmasked = crypto_exor(mask_value, masked)
      unmask_data(
        rest,
        masks,
        index + 1,
        <<resp:bit_string, unmasked:bit_string>>,
      )
    }
  }
}

// TODO:  maybe pull some of this out to take an incomplete frame in a separate
// function?
pub fn frame_from_message(message: BitString) -> Result(Frame, Nil) {
  let assert <<_fin:1, rest:bit_string>> = message
  let assert <<_reserved:3, rest:bit_string>> = rest
  let assert <<opcode:int-size(4), rest:bit_string>> = rest
  case opcode {
    1 | 2 -> {
      // mask
      let assert <<1:1, rest:bit_string>> = rest
      let assert <<payload_length:int-size(7), rest:bit_string>> = rest
      let #(payload_length, rest) = case payload_length {
        126 -> {
          let assert <<length:int-size(16), rest:bit_string>> = rest
          #(length, rest)
        }
        127 -> {
          let assert <<length:int-size(64), rest:bit_string>> = rest
          #(length, rest)
        }
        _ -> #(payload_length, rest)
      }
      let assert <<
        mask1:bit_string-size(8),
        mask2:bit_string-size(8),
        mask3:bit_string-size(8),
        mask4:bit_string-size(8),
        rest:bit_string,
      >> = rest
      case payload_length - bit_string.byte_size(rest) {
        0 -> {
          let data = unmask_data(rest, [mask1, mask2, mask3, mask4], 0, <<>>)
          case opcode {
            1 -> TextFrame(data)
            2 -> BinaryFrame(data)
          }
        }
        need -> {
          let frame_type = case opcode {
            1 -> Text
            2 -> Binary
          }
          Incomplete(
            frame_type,
            length: payload_length,
            mask: [mask1, mask2, mask3, mask4],
            payload: rest,
            remaining: need,
          )
        }
      }
      |> Ok
    }
    8 -> Ok(CloseFrame(payload: <<>>))
  }
}

pub fn frame_to_bit_builder(frame: Frame) -> BitBuilder {
  case frame {
    TextFrame(payload) -> make_frame(1, bit_string.byte_size(payload), payload)
    CloseFrame(payload) -> make_frame(8, bit_string.byte_size(payload), payload)
    BinaryFrame(payload) ->
      make_frame(2, bit_string.byte_size(payload), payload)
    PongFrame -> make_frame(10, 0, <<>>)
    // TODO:  ping should create an actual frame
    PingFrame(..) | Incomplete(..) -> bit_builder.from_bit_string(<<>>)
  }
}

fn make_frame(opcode: Int, length: Int, payload: BitString) -> BitBuilder {
  let length_section = case length {
    length if length > 65_535 -> <<127:7, length:int-size(64)>>
    length if length >= 126 -> <<126:7, length:int-size(16)>>
    _length -> <<length:7>>
  }

  <<1:1, 0:3, opcode:4, 0:1, length_section:bit_string, payload:bit_string>>
  |> bit_builder.from_bit_string
}

pub fn to_text_frame(data: BitString) -> BitBuilder {
  frame_to_bit_builder(TextFrame(data))
}

pub fn to_binary_frame(data: BitString) -> BitBuilder {
  frame_to_bit_builder(BinaryFrame(data))
}

const websocket_key = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

pub fn parse_key(key: String) -> String {
  key
  |> string.append(websocket_key)
  |> crypto_hash(Sha, _)
  |> bit_string.from_string
  |> base.encode64(False)
}

type ShaHash {
  Sha
}

// This is needed because `gleam_crypto` doesn't support `sha1`
external fn crypto_hash(hash: ShaHash, data: String) -> String =
  "crypto" "hash"

external fn crypto_exor(a: BitString, b: BitString) -> BitString =
  "crypto" "exor"
