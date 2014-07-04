package openfl.net;

import haxe.crypto.Sha1;
import haxe.crypto.Base64;
import openfl.errors.Error;
import haxe.io.BytesData;
import haxe.io.BytesData;
import flash.utils.Endian;
import flash.utils.ByteArray;
import flash.utils.ByteArray;
import flash.utils.ByteArray;
import openfl.events.ProgressEvent;
import haxe.crypto.BaseCode;
import haxe.io.BytesOutput;
import haxe.io.Input;
import haxe.io.Bytes;
import flash.events.Event;
import openfl.events.WebSocketEvent;
import openfl.events.EventDispatcher;
import openfl.utils.ByteArray;
import openfl.utils.Endian;

/**
 * ...
 * @author Oussama Gammoudi
 */


class WebSocket extends EventDispatcher {


    private var _ws:Dynamic;


// ELSE
    private static inline var WEB_SOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private static inline var CONNECTING = 0;
    private static inline var OPEN = 1;
    private static inline var CLOSING = 2;
    private static inline var CLOSED = 3;

    private static inline var WEBSOCKET_VERSION = 13;

    private static inline var OPCODE_CONTINUE = 0x0;
    private static inline var OPCODE_TEXT = 0x1;
    private static inline var OPCODE_BINARY = 0x2;
    private static inline var OPCODE_CLOSE = 0x8;
    private static inline var OPCODE_PING = 0x9;
    private static inline var OPCODE_PONG = 0xA;

    private static inline var STATUS_NORMAL_CLOSURE = 1000;
    private static inline var STATUS_NO_CODE = 1005;
    private static inline var STATUS_CLOSED_ABNORMALLY = 1006;
    private static inline var STATUS_CONNECTION_ERROR = 5000;

    private var headersSent:Bool = false;

    private var host:String;
    private var url:String;
    private var port:Int;
    private var key:String = "key";
    private var origin:String = "*";
    private var socket:Socket;

    private var buffer:ByteArray = new ByteArray();
    private var headerState:Int = 0;
    private var readyState:Int = 0;
    private var fragmentsBuffer:ByteArray = null;

    private var requestedProtocols:Array<String> = new Array<String>();

    private var acceptedProtocol:String;
    private var expectedDigest:String;

// common vars

#if html5

	public function connect(host:String,port:Int):Void 
	{

		_ws = untyped __js__("new WebSocket(\"ws://\" + host + \":\" + port)");

		_ws.onopen = onWSOpenHandler;
		_ws.onmessage = onWSMessageHandler;
		_ws.onclose = onWSCloseHandler;
		_ws.onerror = onWSErrorHandler;
		_ws.binaryType = "arraybuffer";

	}
	
	public function send(message:String):Void
	{
		_ws.send(message);
	}

    public function sendBytes(data:ByteArray):Void
    {
        data.endian =Endian.BIG_ENDIAN;
        _ws.send(data.__getBuffer());

    }
	
	private function onWSOpenHandler() {

		this.dispatchEvent(new Event("open"));

	}
	
	private function onWSMessageHandler(message:Dynamic) {
        var messageEvent:WebSocketEvent = new WebSocketEvent("message");
        messageEvent.message = message.data;
        dispatchEvent(messageEvent);

	}
	private function onWSCloseHandler(close:Dynamic) {
        var closeEvent:WebSocketEvent = new WebSocketEvent("close");
        closeEvent.code = close.code;
        closeEvent.wasClean = close.wasClean;
        closeEvent.reason = close.reason;
		dispatchEvent(new WebSocketEvent("close"));
	}
	private function onWSErrorHandler():Void
    {
        dispatchEvent(new WebSocketEvent("error"));
	}


    #else


////////////// ELSE

    public function connect(host:String, port:Int):Void {


        url = "ws://" + host;
        this.host = host;
        this.port = port;
        socket = new Socket();
        socket.addEventListener(Event.CONNECT, onSocketConnect);
        socket.addEventListener(ProgressEvent.SOCKET_DATA, onSocketData);
        socket.connect(host, port);


    }

    public function send(message:String) {

        var frame:Frame = new Frame();
        frame.opcode = OPCODE_TEXT;
        frame.payload = new ByteArray();
        frame.payload.writeUTFBytes(message);
        frame.length = cast frame.payload.length;
        sendFrame(frame);
    }

/**
	 * Sends binary data over connection
	 */

    public function sendBytes(data:ByteArray) {
        var frame:Frame = new Frame();
        frame.opcode = OPCODE_BINARY;
        frame.payload = data;
        frame.length = data.length;
        sendFrame(frame);
    }

    private function onSocketConnect(e:Event):Void {
        sendHandShake();
        dispatchEvent(new Event("open"));
    }


    private function onSocketData(event:ProgressEvent):Void {
        var pos:Int = buffer.length;
        socket.readBytes(buffer, pos);
        var length:Int = cast buffer.length;
        while (pos < length) {
            if (headerState < 4) {
// try to find "\r\n\r\n"
                if ((headerState == 0 || headerState == 2) && buffer[pos] == 0x0d) {
                    ++headerState;
                } else if ((headerState == 1 || headerState == 3) && buffer[pos] == 0x0a) {
                    ++headerState;
                } else {
                    headerState = 0;
                }
                if (headerState == 4) {
                    var headerStr:String = readUTFBytes(buffer, 0, pos + 1);
                    Lib.trace("response header:\n" + headerStr);
                    if (!validateHandshake(headerStr)) return;
                    removeBufferBefore(pos + 1);
                    pos = -1;
                    readyState = OPEN;
                    this.dispatchEvent(new Event("open"));
                }
            } else {
                var frame:Frame = parseFrame();
                Lib.trace("frame:"+frame.opcode);
                if (frame.opcode != -1) {
                    removeBufferBefore(frame.length);
                    pos = -1;
                    if (frame.rsv != 0) {
                        close(1002, "RSV must be 0.");
                    } else if (frame.mask) {
                        close(1002, "Frame from server must not be masked.");
                    } else if (frame.opcode >= 0x08 && frame.opcode <= 0x0f && frame.payload.length >= 126) {
                        close(1004, "Payload of control frame must be less than 126 bytes.");
                    } else {
                        switch (frame.opcode) {
                            case OPCODE_CONTINUE:
                                if (fragmentsBuffer == null) {
                                    close(1002, "Unexpected continuation frame");
                                } else {
                                    fragmentsBuffer.writeBytes(frame.payload);
                                    if (frame.fin) {
                                       var  data = readUTFBytes(fragmentsBuffer, 0, fragmentsBuffer.length);
                                        try {
                                            var messageEvent:WebSocketEvent = new WebSocketEvent("message");
                                            messageEvent.message = StringTools.urlEncode(data);
                                            this.dispatchEvent(messageEvent);
                                        } catch (ex:Dynamic) {
                                            close(1007, "URIError while encoding the received data.");
                                        }
                                        fragmentsBuffer = null;
                                    }
                                }
                                break;
                            case OPCODE_TEXT:
                                if (frame.fin) {
                                    var data:String = readUTFBytes(frame.payload, 0, frame.payload.length);
                                    try {
                                        var messageEvent:WebSocketEvent = new WebSocketEvent("message");
                                        messageEvent.message = StringTools.urlEncode(data);
                                        this.dispatchEvent(messageEvent);
                                    } catch (ex:Dynamic) {
                                        close(1007, "URIError while encoding the received data.");
                                    }
                                } else {
                                    fragmentsBuffer = new ByteArray();
                                    fragmentsBuffer.writeBytes(frame.payload);
                                }
                                break;
                            case OPCODE_BINARY:
                                if (frame.fin) {
                                    try {
                                        var messageEvent:WebSocketEvent = new WebSocketEvent("message");
                                        messageEvent.message = frame.payload;
                                        this.dispatchEvent(messageEvent);
                                    } catch (ex:Dynamic) {
                                        close(1007, "URIError while encoding the received data.");
                                    }
                                } else {
                                    fragmentsBuffer = new ByteArray();
                                    fragmentsBuffer.writeBytes(frame.payload);
                                }
                                close(1003, "Received binary data, which is not supported.");
                                break;
                            case OPCODE_CLOSE:
// Extracts code and reason string.
                                var code:Int = STATUS_NO_CODE;
                                var reason:String = "";
                                if (frame.payload.length >= 2) {
                                    frame.payload.endian = Endian.BIG_ENDIAN;
                                    frame.payload.position = 0;
                                    code = frame.payload.readUnsignedShort();
                                    reason = readUTFBytes(frame.payload, 2, frame.payload.length - 2);
                                }
                                Lib.trace("received closing frame");
                                close(code, reason, "server");
                                break;
                            case OPCODE_PING:
                                var frame:Frame = new Frame();
                                frame.opcode = OPCODE_PONG;
                                frame.payload = frame.payload;
                                frame.length = frame.payload.length;
                                sendFrame(frame);
                                break;
                            case OPCODE_PONG:
                                break;
                            default:
                                close(1002, "Received unknown opcode: " + frame.opcode);
                                break;
                        }
                    }
                }
            }
            ++pos;
        }
    }

    private function sendHandShake():Void {

        var encodedKey = encodeBase64(key);
        Lib.trace("key"+encodedKey);

        expectedDigest = Base64.encode(Sha1.make(Bytes.ofString(encodedKey+WEB_SOCKET_GUID)));
        var headers = new Array<String>();

        headers.push("GET " + url + " HTTP/1.1");
        headers.push("Host: " + host + ":" + port);
        headers.push("Upgrade: websocket");
        headers.push("Connection: Upgrade");
        headers.push("Sec-WebSocket-Key: " + encodedKey);
        headers.push("Sec-WebSocket-Version: " + WEBSOCKET_VERSION);
        headers.push("Origin: " + origin);

// send headers
        var header = headers.join("\r\n") + "\r\n\r\n";

        socket.writeBytes(cast Bytes.ofString(header));
        socket.flush();
        headersSent = true;
    }


/**
	 * Reads a complete WebSocket frame
	 */

    private inline function recvFrame() {
        var opcode = socket.readByte();
        var len = socket.readByte();

        var final = opcode & 0x80 != 0;
        opcode = opcode & 0x0F;
        var mask = len >> 7 == 1;
        len = len & 0x7F;

        if (len == 126) {
            var lenByte0 = socket.readByte();
            var lenByte1 = socket.readByte();
            len = (lenByte0 << 8) + lenByte1;
        }
        else if (len > 126) {
            var lenByte0 = socket.readByte();
            var lenByte1 = socket.readByte();
            var lenByte2 = socket.readByte();
            var lenByte3 = socket.readByte();
            len = (lenByte0 << 24) + (lenByte1 << 16) + (lenByte2 << 8) + lenByte3;
        }


        var maskba:ByteArray = new ByteArray();
        maskba.endian = Endian.BIG_ENDIAN;
        socket.readBytes(maskba, 0, 4);

        var maskKey:Bytes = (mask ? cast maskba : null);


        var ba:ByteArray = new ByteArray();
        ba.endian = Endian.BIG_ENDIAN;
        socket.readBytes(ba, 0, len);
        var payload:Bytes = cast ba;
        if (mask) {
// unmask data
            for (i in 0...payload.length) {
                payload.set(i, payload.get(i) ^ maskKey.get(i % 4));
            }
        }

        return {
        opcode: opcode,
        mask: mask,
        final: final,
        bytes: payload
        };
    }

    private function encodeBase64(content:String):String {
        var suffix = switch (content.length % 3) {
            case 2: "=";
            case 1: "==";
            default: "";
        };
        return BaseCode.encode(content, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") + suffix;
    }

    private function randomInt(min:UInt, max:UInt):UInt {
        return min + Math.floor(Math.random() * ((max) - min + 1));
    }

    private function sendFrame(frame:Frame):Bool {

        var plength:UInt = frame.payload.length;

// Generates a mask.


        var header:ByteArray = new ByteArray();

// FIN + RSV + opcode
        header.writeByte((frame.fin ? 0x80 : 0x00) | (frame.rsv << 4) | frame.opcode);
        var masked = frame.mask ? 0x80 : 0x00;
        if (plength <= 125) {
            header.writeByte(masked | plength); // Masked + length
        } else if (plength > 125 && plength < 65536) {
            header.writeByte(masked | 126); // Masked + 126
            header.writeShort(plength);
        } else if (plength >= 65536 && plength < 4294967296) {
            header.writeByte(masked | 127); // Masked + 127
            header.writeUnsignedInt(0); // zero high order bits
            header.writeUnsignedInt(plength);
        } else {
//fatal("Send frame size too large");
        }

        var maskedPayload:ByteArray;
        if (frame.mask) {
            var mask:ByteArray = new ByteArray();
            for (i in 0...4) {
                mask.writeByte(randomInt(0, 255));
            }
            header.writeBytes(mask);
            maskedPayload = new ByteArray();
            maskedPayload.writeBytes(frame.payload, 0, frame.payload.length);
            for (i in 0...frame.payload.length) {
                maskedPayload[i] = mask[i % 4] ^ frame.payload[i];
            }


        } else {
            maskedPayload = frame.payload;
        }
//

        try {
            socket.writeBytes(header);
            socket.writeBytes(maskedPayload);
            socket.flush();
        } catch (ex:Error) {

         Lib.trace("Error while sending frame: " + ex.message);
       /* setTimeout(function():Void {
        if (readyState != CLOSED) {
        close(STATUS_CONNECTION_ERROR);

        }
        }, 0);*/

            return false;
        }
        return true;

    }

    private function validateHandshake(headerStr:String):Bool {
        var lines:Array<String> = headerStr.split("\r\n");
        var response = ~/^HTTP\/1.1 101 /;
        if (!response.match(lines[0])) {
            onConnectionError("bad response: " + lines[0]);
            return false;
        }
        var header:Map<String,String> = new Map<String,String>();
        var lowerHeader:Map<String,String> = new Map<String,String>();
        for (i in 1...lines.length) {
            if (lines[i].length == 0) continue;
            lines[i] = StringTools.replace(lines[i]," ","");
            Lib.trace(lines[i]);
            var m:Array<String> = lines[i].split(":");
            Lib.trace(m);
            if (m.length!=2) {
                onConnectionError("failed to parse response header line: " + lines[i]);
                return false;
            }
            var key:String = m[0].toLowerCase();
            var value:String = m[1];
            header[key] = value;
            lowerHeader[key] = value.toLowerCase();
        }
        if (lowerHeader["upgrade"] != "websocket") {
            onConnectionError("invalid Upgrade: " + header["Upgrade"]);
            return false;
        }
        if (lowerHeader["connection"] != "upgrade") {
            onConnectionError("invalid Connection: " + header["Connection"]);
            return false;
        }
        if (!lowerHeader.exists("sec-websocket-accept")) {
            onConnectionError(
                "The WebSocket server speaks old WebSocket protocol, " +
                "which is not supported by web-socket-js. " +
                "It requires WebSocket protocol HyBi 10. " +
                "Try newer version of the server if available.");
            return false;
        }
        var replyDigest:String = header["sec-websocket-accept"];
        if (replyDigest != expectedDigest) {
            onConnectionError("digest doesn't match: " + replyDigest + " != " + expectedDigest);
            return false;
        }
        if (requestedProtocols.length > 0) {
            acceptedProtocol = header["sec-websocket-protocol"];
            if (requestedProtocols.indexOf(acceptedProtocol) < 0) {
                onConnectionError("protocol doesn't match: '" +
                acceptedProtocol + "' not in '" + requestedProtocols.join(",") + "'");
                return false;
            }
        }
        return true;
    }

    private function parseFrame():Frame {

        var frame:Frame = new Frame();
        var hlength:UInt = 0;
        var plength:UInt = 0;

        hlength = 2;
        if (buffer.length < hlength) {
            return null;
        }

        frame.fin = (buffer[0] & 0x80) != 0;
        frame.rsv = (buffer[0] & 0x70) >> 4;
        frame.opcode = buffer[0] & 0x0f;
// Payload unmasking is not implemented because masking frames from server
// is not allowed. This field is used only for error checking.
        frame.mask = (buffer[1] & 0x80) != 0;
        plength = buffer[1] & 0x7f;

        if (plength == 126) {

            hlength = 4;
            if (buffer.length < hlength) {
                return null;
            }
            buffer.endian = Endian.BIG_ENDIAN;
            buffer.position = 2;
            plength = buffer.readUnsignedShort();

        } else if (plength == 127) {

            hlength = 10;
            if (buffer.length < hlength) {
                return null;
            }
            buffer.endian = Endian.BIG_ENDIAN;
            buffer.position = 2;
// Protocol allows 64-bit length, but we only handle 32-bit
            var big:UInt = buffer.readUnsignedInt(); // Skip high 32-bits
            plength = buffer.readUnsignedInt(); // Low 32-bits
            if (big != 0) {
//fatal("Frame length exceeds 4294967295. Bailing out!");
                return null;
            }

        }

        if (buffer.length < hlength + plength) {
            return null;
        }

        frame.length = hlength + plength;
        frame.payload = new ByteArray();
        buffer.position = hlength;
        buffer.readBytes(frame.payload, 0, plength);
        return frame;

    }

    private function readUTFBytes(buffer:ByteArray, start:Int, numBytes:Int):String {
        buffer.position = start;
        var data:String = "";
        for (i in start...(start + numBytes)) {
// Workaround of a bug of ByteArray#readUTFBytes() that bytes after "\x00" is discarded.
        if (buffer[i] == 0x00) {
        data += buffer.readUTFBytes(i - buffer.position) + "\x00";
        buffer.position = i + 1;
        }
        }
        data += buffer.readUTFBytes(start + numBytes - buffer.position);
        return data;
    }

    private function onConnectionError(message:String):Void {
        if (readyState == CLOSED) return;
        Lib.trace(message);
        close(STATUS_CONNECTION_ERROR);
    }

    private function removeBufferBefore(pos:Int):Void {
        if (pos == 0) return;
        var nextBuffer:ByteArray = new ByteArray();
        buffer.position = pos;
        buffer.readBytes(nextBuffer);
        buffer = nextBuffer;
    }

    public function close(code:Int, ?reason:String="",?origin:String = "client"):Void {

        var closeEvent:WebSocketEvent = new WebSocketEvent("close");
        closeEvent.code = code;
        closeEvent.reason = reason;
        closeEvent.wasClean = false;
        dispatchEvent(closeEvent);
    }

#end
}


private class Frame {

    public var fin:Bool = true;
    public var rsv:Int = 0;
    public var opcode:Int = -1;
    public var payload:ByteArray;

// Fields below are not used when used as a parameter of sendFrame().
    public var length:UInt = 0;
    public var mask:Bool = true;

    public function new() {

    }

}
/*
private class SHA {
    public static var b64pad:String  = "="; /* base-64 pad character. "=" for strict RFC compliance
    public static var chrsz:UInt   = 8;

    public static function core_sha1 (x:Array<Float>, len:Float):Array<Float> {
/* append padding
        x[len >> 5] |= 0x80 << (24 - len % 32);
        x[((len + 64 >> 9) << 4) + 15] = len;

        var w:Array = new Array(80);
        var a:Float =  1732584193;
        var b:Float = -271733879;
        var c:Float = -1732584194;
        var d:Float =  271733878;
        var e:Float = -1009589776;

        var i:Float = 0;
        while( i < x.length ) {
            var olda:Float = a;
            var oldb:Float = b;
            var oldc:Float = c;
            var oldd:Float = d;
            var olde:Float = e;

            for(j in 0...80) {
                if(j < 16) w[j] = x[i + j];
                else w[j] = rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
                var t:Float = safe_add (safe_add (rol (a, 5), sha1_ft (j, b, c, d)), safe_add (safe_add (e, w[j]), sha1_kt (j)));
                e = d;
                d = c;
                c = rol(b, 30);
                b = a;
                a = t;
            }

            a = safe_add(a, olda);
            b = safe_add(b, oldb);
            c = safe_add(c, oldc);
            d = safe_add(d, oldd);
            e = safe_add(e, olde);

            i += 16;
        }

        return [a, b, c, d, e];
    }

    public static function b64_sha1 (string:String):String {
        return binb2b64 (core_sha1 (str2binb (string), string.length * chrsz));
    }

    public static function str2binb (str:String):Array<Float> {
        var bin:Array = new Array ();
        var mask:Float = (1 << chrsz) - 1;
        var i:Float = 0;
        while ( i < str.length * chrsz){

        bin[i>>5] |= (str.charCodeAt (i / chrsz) & mask) << (32 - chrsz - i%32);
        i += chrsz;
        };
        return bin;
    }

    public static function safe_add (x:Float, y:Float):Float {
        var lsw:Float = (x & 0xFFFF) + (y & 0xFFFF);
        var msw:Float = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
    }

    public static function binb2b64 (binarray:Array<Float>):String {
        var tab:String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var str:String = "";
        var i:Int = 0;
        while( i < binarray.length * 4) {
        var triplet:Float = cast (((binarray[i   >> 2] >> 8 * (3 -  i   %4)) & 0xFF) << 16)
        | (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 )
        |  ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
        for(j in 0...4) {
        if (i * 8 + j * 6 > binarray.length * 32) str += b64pad;
        else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
        }
        i += 3;
        }
        return str;
    }




}

*/
