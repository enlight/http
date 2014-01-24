Module:    httpi
Synopsis:  WebSocket support (RFC 6455)
Author:    Vadim Macagon
Copyright: See LICENSE file in this distribution.

// Any resource that is served over a websocket should inherit from <websocket-resource>.
define open class <websocket-resource> (<resource>)
  slot socket :: <tcp-socket>;
  // The protocol chosen by the server out of the protocols supported by the client,
  // or #f if none was chosen.
  slot protocol :: false-or(<byte-string>) = #f;
  // The extensions chosen by the server out of the extensions supported by the client,
  // or #f if none were chosen.
  slot extensions :: false-or(<byte-string>) = #f;
  // These frames will be sent to the client.
  slot outgoing-frames :: <deque>,
    init-function: curry(make, <deque>);
end;

// The server should select a protocol and extensions out of those supported by the client.
define generic select-protocol-and-extensions
    (resource :: <websocket-resource>, client-protocols :: <object>, client-extensions :: <object>)
 => (successful? :: <boolean>);

// This will be called for every frame received from the client (after it's unmasked).
define generic incoming-frame-callback
    (resource :: <websocket-resource>, frame :: <websocket-frame>) => ();

// Override this method in a <websocket-resource> subclass to handle protocol and extension
// negotiation
define method respond-to-get
    (resource :: <websocket-resource>, #key)
  let response = current-response();
  response.response-code := 101; // Switching Protocols
  set-header(response, "Upgrade", "websocket");
  set-header(response, "Connection", "Upgrade");
  let request = current-request();
  let accept-code = concatenate(get-header(request, "Sec-WebSocket-Key", parsed: #t),
                                "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
  set-header(response, "Sec-WebSocket-Accept", sha1(accept-code));
  let client-protocols = get-header(request, "Sec-WebSocket-Protocol", parsed: #t);
  let client-extensions = get-header(request, "Sec-WebSocket-Extensions", parsed: #t);
  if (select-protocol-and-extensions(resource, client-protocols, client-extensions))
    if (resource.protocol)
      set-header(response, "Sec-WebSocket-Protocol", resource.protocol);
    end if;
    if (resource.extensions)
      set-header(response, "Sec-WebSocket-Extensions", resource.extensions);
    end if;
  end if;
  resource.socket := request.request-socket;
  response.websocket-server := resource;
end;

define method process-frames
    (server :: <websocket-resource>)
  // TODO: deal with errors
  while (#t)
    let frame = read-frame(server);
    incoming-frame-callback(server, frame);
    write-frame(server, server.outgoing-frames.pop());
  end;
end;

define open class <websocket-frame> (<object>)
  slot fin :: <bit>;
  slot rsv :: <bit-vector> = make(<bit-vector>, size: 3);
  slot opcode :: <integer>,
    init-value: 0;
  slot payload-length :: <integer>, // note: less than 64 bits!
    init-value: 0;
  slot masking-key :: <byte-string>;
  slot payload :: <byte-string>;
end;

// Mask/Unmask the payload of the frame as per http://tools.ietf.org/html/rfc6455#section-5.3
define method toggle-payload-mask!
    (frame :: <websocket-frame>, masking-key :: <byte-string>) => ();
  for (i from 0 to frame.payload.size())
    frame.payload[i] := logxor(frame.payload[i], frame.masking-key[modulo(i, 4)]);
  end;
end method toggle-payload-mask!;

define method read-frame
    (server :: <websocket-resource>) => (frame :: <websocket-frame>)
  // TODO: handle <incomplete-read-error> and <end-of-stream-error>
  let buffer = read(server.socket, 2);
  let frame = make(<websocket-frame>);
  frame.fin := ash(logand(buffer[0], #b10000000), -7);
  frame.rsv[0] := ash(logand(buffer[0], #b01000000), -6);
  frame.rsv[1] := ash(logand(buffer[0], #b00100000), -5);
  frame.rsv[2] := ash(logand(buffer[0], #b00010000), -4);
  frame.opcode := logand(buffer[0], #x0F);
  let frame-masked? = (ash(logand(buffer[1], #b10000000), -7) ~= 0);
  frame.payload-length := logand(buffer[1], #b01111111);

  if (frame.payload-length = 126)
    buffer := read(server.socket, 2);
    frame.payload-length := logand(ash(as(<integer>, buffer[0]), 8), as(<integer>, buffer[1]));
  elseif (frame.payload-length = 127)
    buffer := read(server.socket, 8);
    // TODO: signal an error since the length is a 64-bit unsigned integer that can't be easily
    // stored in Dylan atm.
  end;

  let masking-key = #f;
  if (frame-masked?)
    masking-key := read(server.socket, 4);
  else
    // TODO: signal an error, frames sent by the client must always be masked, connection
    // should be terminated
  end;

  frame.payload := read(server.socket, frame.payload-length);
  if (frame-masked?)
    toggle-payload-mask!(frame, masking-key);
  end;

  frame;
end;

define method write-frame
    (server :: <websocket-resource>, frame :: <websocket-frame>)
  let header-length = 2;
  let payload-length-prefix = frame.payload-length;
  if (frame.payload-length >= 65536)
    header-length := header-length + 8;
    payload-length-prefix := 127;
    // TODO: signal an error since the length is a 64-bit unsigned integer that can't be easily
    // stored in Dylan atm.
  elseif (frame.payload-length > 125)
    header-length := header-length + 2;
    payload-length-prefix := 126;
  elseif (frame.payload-length < 0)
    // TODO: signal an error
  end;

  let header = make(<byte-string>, size: header-length);
  header[0] := logior(ash(as(<byte>, frame.fin), 7),
                      ash(as(<byte>, frame.rsv[0]), 6),
                      ash(as(<byte>, frame.rsv[1]), 5),
                      ash(as(<byte>, frame.rsv[2]), 4),
                      as(<byte>, frame.opcode));
  header[1] := payload-length-prefix;
  if (frame.payload-length > 125)
    header[2] := as(<byte>, ash(frame.payload-length, -8));
    header[3] := as(<byte>, ash(ash(frame.payload-length, 8), -8));
  end;

  write(server.socket, header, end: header-length);
  write(server.socket, frame.payload, end: frame.payload-length);
end;
