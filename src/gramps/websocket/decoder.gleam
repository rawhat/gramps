//// Incremental, bounded decoding for uncompressed WebSocket messages.
////
//// Declared lengths are checked before payload bytes are retained or unmasked.
//// One call returns at most one message, leaving later input with the caller.
//// Fragment state survives TCP boundaries, and control frames do not consume
//// or reset the unfinished message's byte budget. Compression is deliberately
//// unsupported: a compressed input limit cannot bound decompressed output.

import gleam/bit_array
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/result
import gramps/websocket

/// Why a bounded connection must stop decoding.
pub type Error {
  /// A declared frame exceeds the configured payload limit.
  FrameTooLarge

  /// A complete message or its cumulative fragments exceed the limit.
  MessageTooLarge

  /// Compression was requested without a bounded decompressor.
  CompressionUnsupported

  /// The header or fragment sequence violates the WebSocket protocol.
  InvalidFrame
}

/// The retained state for one connection; native socket buffers are separate.
pub opaque type Decoder {
  Decoder(
    max_frame: Int,
    max_message: Int,
    buffer: BitArray,
    fragment: Option(websocket.DataFrame),
  )
}

/// One incremental decoding result.
pub type Decoded {
  /// More input is needed; only the admitted partial frame is retained.
  More(decoder: Decoder)

  /// One complete message or control frame, and input not yet inspected.
  Frame(frame: websocket.Frame, decoder: Decoder, rest: BitArray)
}

/// Creates a connection decoder with positive payload limits in bytes.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(decoder) = new(max_frame_bytes: 1024, max_message_bytes: 4096)
/// ```
pub fn new(
  max_frame_bytes frame: Int,
  max_message_bytes message: Int,
) -> Result(Decoder, Nil) {
  case frame > 0 && message > 0 {
    True -> Ok(Decoder(frame, message, <<>>, None))
    False -> Error(Nil)
  }
}

/// Reads at most one complete message, without collecting subsequent frames.
///
/// Feed `More` the next TCP chunk. After `Frame`, process that frame before
/// passing its `rest` back with the returned decoder. Limits apply to payload
/// bytes; a partial header additionally retains at most fourteen bytes.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(decoder) = new(1024, 4096)
/// next(decoder, <<0x81, 2, "ok":utf8>>)
/// ```
pub fn next(decoder: Decoder, data: BitArray) -> Result(Decoded, Error) {
  use #(prefix, rest) <- result.try(fill(decoder.buffer, data, 2))
  case prefix {
    <<fin:1, reserved:3, opcode:4, masked:1, short:7, _:bits>> -> {
      use Nil <- result.try(validate_flags(fin, reserved, opcode, short))
      let length_bytes = case short {
        126 -> 2
        127 -> 8
        _ -> 0
      }
      use #(header, rest) <- result.try(fill(prefix, rest, 2 + length_bytes))
      case payload_size(header, short) {
        None -> Ok(More(Decoder(..decoder, buffer: header)))
        Some(size) -> {
          use Nil <- result.try(admit(decoder, opcode, size))
          let mask_bytes = case masked {
            0 -> 0
            _ -> 4
          }
          read_frame(
            decoder,
            header,
            rest,
            2 + length_bytes + mask_bytes + size,
          )
        }
      }
    }
    _ -> Ok(More(Decoder(..decoder, buffer: prefix)))
  }
}

// Copy only the bytes required for the current header or admitted frame. A
// later frame in the same TCP chunk remains a slice owned by the caller.
fn fill(
  buffer: BitArray,
  input: BitArray,
  target: Int,
) -> Result(#(BitArray, BitArray), Error) {
  let count =
    int.max(
      0,
      int.min(target - bit_array.byte_size(buffer), bit_array.byte_size(input)),
    )
  case input {
    <<taken:bytes-size(count), rest:bits>> ->
      Ok(#(<<buffer:bits, taken:bits>>, rest))
    _ -> Error(InvalidFrame)
  }
}

fn validate_flags(
  fin: Int,
  reserved: Int,
  opcode: Int,
  short: Int,
) -> Result(Nil, Error) {
  case reserved, opcode {
    4, _ -> Error(CompressionUnsupported)
    value, _ if value != 0 -> Error(InvalidFrame)
    _, 0 | _, 1 | _, 2 -> Ok(Nil)
    _, 8 | _, 9 | _, 10 if fin == 1 && short <= 125 -> Ok(Nil)
    _, _ -> Error(InvalidFrame)
  }
}

fn payload_size(header: BitArray, short: Int) -> Option(Int) {
  case short, header {
    126, <<_:16, size:16, _:bits>> -> Some(size)
    127, <<_:16, size:64, _:bits>> -> Some(size)
    126, _ | 127, _ -> None
    _, _ -> Some(short)
  }
}

fn admit(decoder: Decoder, opcode: Int, size: Int) -> Result(Nil, Error) {
  case size > decoder.max_frame {
    True -> Error(FrameTooLarge)
    False ->
      case opcode, decoder.fragment {
        0, None -> Error(InvalidFrame)
        0, Some(fragment) -> {
          case payload_bytes(fragment) + size > decoder.max_message {
            True -> Error(MessageTooLarge)
            False -> Ok(Nil)
          }
        }
        1, Some(_) | 2, Some(_) -> Error(InvalidFrame)
        1, None | 2, None if size > decoder.max_message -> Error(MessageTooLarge)
        _, _ -> Ok(Nil)
      }
  }
}

fn payload_bytes(frame: websocket.DataFrame) -> Int {
  case frame {
    websocket.TextFrame(data) | websocket.BinaryFrame(data) ->
      bit_array.byte_size(data)
  }
}

fn append(
  fragment: websocket.DataFrame,
  data: BitArray,
) -> websocket.DataFrame {
  case fragment {
    websocket.TextFrame(previous) ->
      websocket.TextFrame(<<previous:bits, data:bits>>)
    websocket.BinaryFrame(previous) ->
      websocket.BinaryFrame(<<previous:bits, data:bits>>)
  }
}

fn read_frame(
  decoder: Decoder,
  header: BitArray,
  input: BitArray,
  total: Int,
) -> Result(Decoded, Error) {
  use #(buffer, rest) <- result.try(fill(header, input, total))
  case bit_array.byte_size(buffer) < total {
    True -> Ok(More(Decoder(..decoder, buffer: buffer)))
    False -> {
      use #(parsed, _) <- result.try(
        websocket.decode_frame(buffer, None)
        |> result.replace_error(InvalidFrame),
      )
      let decoder = Decoder(..decoder, buffer: <<>>)
      case parsed, decoder.fragment {
        websocket.Complete(websocket.Control(_) as frame), _ ->
          Ok(Frame(frame, decoder, rest))
        websocket.Complete(websocket.Data(_) as frame), None ->
          Ok(Frame(frame, decoder, rest))
        websocket.Incomplete(websocket.Data(data)), None ->
          next(Decoder(..decoder, fragment: Some(data)), rest)
        websocket.Incomplete(websocket.Continuation(_, data)), Some(fragment) ->
          next(Decoder(..decoder, fragment: Some(append(fragment, data))), rest)
        websocket.Complete(websocket.Continuation(_, data)), Some(fragment) ->
          Ok(Frame(
            websocket.Data(append(fragment, data)),
            Decoder(..decoder, fragment: None),
            rest,
          ))
        _, _ -> Error(InvalidFrame)
      }
    }
  }
}
