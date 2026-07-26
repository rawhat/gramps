import gleam/bit_array
import gleam/bytes_tree
import gleam/crypto
import gleam/http.{Http}
import gleam/http/request
import gleam/http/response
import gleam/list
import gleam/option.{None, Some}
import gleeunit
import gramps/debug
import gramps/http as gramps_http
import gramps/websocket

pub fn main() {
  gleeunit.main()
}

pub fn it_should_encode_text_frame_without_mask_test() {
  assert websocket.encode_text_frame("hello, world!", None, None)
    == bytes_tree.from_bit_array(<<1:1, 0:3, 1:4, 0:1, 13:7, "hello, world!">>)
}

pub fn it_should_make_empty_pong_frame_with_mask_test() {
  let mask = <<26, 237, 79, 237>>
  assert websocket.encode_pong_frame(<<>>, Some(mask))
    == bytes_tree.from_bit_array(<<1:1, 0:3, 10:4, 1:1, 0:7, mask:bits>>)
}

pub fn it_should_decode_close_frame_with_reason_test() {
  let msg = <<136, 12, 3, 233, 103, 111, 105, 110, 103, 32, 97, 119, 97, 121>>
  assert websocket.decode_frame(msg, None)
    == Ok(
      #(
        websocket.Complete(
          websocket.Control(
            websocket.CloseFrame(websocket.GoingAway(<<"going away">>)),
          ),
        ),
        <<>>,
      ),
    )
}

pub fn it_should_encode_close_frame_with_reason_test() {
  let mask = <<26, 237, 79, 237>>
  let masked = websocket.apply_mask(<<1001:16, "going away">>, Some(mask))
  assert websocket.encode_close_frame(
      websocket.GoingAway(<<"going away">>),
      Some(mask),
    )
    == bytes_tree.from_bit_array(<<
      1:1,
      0:3,
      8:4,
      1:1,
      bit_array.byte_size(masked):7,
      mask:bits,
      masked:bits,
    >>)
}

pub fn it_should_parse_valid_request_test() {
  let req =
    "GET /index.html HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0
Accept: text/xml,application/xml,application/xhtml+xml,text/html*/*
Accept-Language: en-us
Accept-Charset: ISO-8859-1,utf-8
Connection: keep-alive

"

  let expected =
    request.new()
    |> request.set_body(Nil)
    |> request.set_path("/index.html")
    |> request.set_host("www.example.com")
    |> request.set_scheme(Http)
    |> request.set_header("connection", "keep-alive")
    |> request.set_header("accept-charset", "ISO-8859-1,utf-8")
    |> request.set_header("accept-language", "en-us")
    |> request.set_header(
      "accept",
      "text/xml,application/xml,application/xhtml+xml,text/html*/*",
    )
    |> request.set_header("user-agent", "Mozilla/5.0")
    |> request.set_header("host", "www.example.com")

  let read =
    req
    |> bit_array.from_string
    |> gramps_http.read_request
  assert read == Ok(#(expected, <<>>))
}

pub fn it_should_parse_valid_response_test() {
  let resp =
    "HTTP/1.1 201 Created
Location: http://localhost/objectserver/restapi/alerts/status/kf/12481%3ANCOMS
Cache-Control: no-cache
Server: libnhttpd
Date: Wed Jul 4 15:31:53 2012
Connection: Keep-Alive
Content-Type: application/json;charset=UTF-8
Content-Length: 304

{
	\"entry\":	{
		\"affectedRows\": 1,
		\"keyField\": \"12481%3ANCOMS\",
		\"uri\": \"http://localhost/objectserver/restapi/alerts/status/kf/12481%3ANCOMS\"
	}
}"

  let expected =
    response.new(201)
    |> response.set_body(Nil)
    |> response.set_header("content-length", "304")
    |> response.set_header("content-type", "application/json;charset=UTF-8")
    |> response.set_header("connection", "Keep-Alive")
    |> response.set_header("date", "Wed Jul 4 15:31:53 2012")
    |> response.set_header("server", "libnhttpd")
    |> response.set_header("cache-control", "no-cache")
    |> response.set_header(
      "location",
      "http://localhost/objectserver/restapi/alerts/status/kf/12481%3ANCOMS",
    )

  assert gramps_http.read_response(bit_array.from_string(resp))
    == Ok(
      #(expected, <<
        "{
	\"entry\":	{
		\"affectedRows\": 1,
		\"keyField\": \"12481%3ANCOMS\",
		\"uri\": \"http://localhost/objectserver/restapi/alerts/status/kf/12481%3ANCOMS\"
	}
}":utf8,
      >>),
    )
}

pub fn it_should_return_literal_bits_simple_test() {
  let bits = <<1:1>>
  let literal = debug.literal_bits(bits, [])

  assert literal == [1]
}

pub fn it_should_return_literal_bits_complex_test() {
  let bits = <<129, 7, 111, 112, 101, 110, 101, 100, 33>>
  let literal = debug.literal_bits(bits, [])

  assert literal
    == [
      1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0,
      1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1,
      1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
    ]
}

// --- masking ---------------------------------------------------------------

@external(erlang, "crypto", "exor")
fn crypto_exor(a a: BitArray, b b: BitArray) -> BitArray

/// The previous implementation, kept here as the thing to agree with.
///
/// It walked the payload a byte at a time, picking a mask byte by index.
fn mask_byte_by_byte(
  data: BitArray,
  masks: List(BitArray),
  index: Int,
  resp: BitArray,
) -> BitArray {
  case data {
    <<masked:bits-size(8), rest:bits>> -> {
      let assert [one, two, three, four] = masks
      let mask_value = case index % 4 {
        0 -> one
        1 -> two
        2 -> three
        3 -> four
        _ -> panic as "a value mod 4 is not 0, 1, 2, or 3"
      }
      let unmasked = crypto_exor(mask_value, masked)
      mask_byte_by_byte(rest, masks, index + 1, <<resp:bits, unmasked:bits>>)
    }
    _ -> resp
  }
}

fn split_mask(mask: BitArray) -> List(BitArray) {
  let assert <<
    one:bytes-size(1),
    two:bytes-size(1),
    three:bytes-size(1),
    four:bytes-size(1),
  >> = mask
  [one, two, three, four]
}

pub fn masking_matches_the_byte_at_a_time_result_test() {
  let mask = <<0x37, 0xfa, 0x21, 0x3d>>

  // Sizes chosen to cover every case that tends to break a rewrite: empty,
  // shorter than the mask, not a multiple of it, and either side of the two
  // frame-length boundaries where the header grows.
  [0, 1, 2, 3, 4, 5, 7, 8, 125, 126, 127, 255, 1000, 65_535, 65_536]
  |> list.each(fn(size) {
    let payload = crypto.strong_random_bytes(size)

    assert websocket.apply_mask(payload, Some(mask))
      == mask_byte_by_byte(payload, split_mask(mask), 0, <<>>)
  })
}

pub fn masking_is_its_own_inverse_test() {
  // XOR with the same key twice is the identity, which is what lets the same
  // routine both mask and unmask.
  let mask = <<0x01, 0x02, 0x03, 0x04>>
  let payload = <<"the quick brown fox":utf8>>

  let masked = websocket.apply_mask(payload, Some(mask))
  assert masked != payload
  assert websocket.apply_mask(masked, Some(mask)) == payload
}

pub fn the_rfc_6455_example_test() {
  // RFC 6455 section 5.7: "Hello" under mask 0x37fa213d is 0x7f9f4d5158.
  let masked =
    websocket.apply_mask(
      <<"Hello":utf8>>,
      option.Some(<<0x37, 0xfa, 0x21, 0x3d>>),
    )

  assert masked == <<0x7f, 0x9f, 0x4d, 0x51, 0x58>>
}

pub fn an_unmasked_frame_is_left_alone_test() {
  let payload = <<"unchanged":utf8>>
  assert websocket.apply_mask(payload, None) == payload
}
