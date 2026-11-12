import Foundation
import CZlib

/// Local profile wire format used by official libbox 1.14.4:
/// message type 3, version 1, gzip(uvarint/name, int32/type=0, uvarint/config).
public enum PortableProfile {
    public static func encode(name: String, config: Data) throws -> Data {
        _ = try JSONSerialization.jsonObject(with: config)
        let label = Data(name.utf8)
        var payload = varint(label.count); payload.append(label)
        payload.append(contentsOf: [0, 0, 0, 0])
        payload.append(varint(config.count)); payload.append(config)
        var result = Data([3, 1]); result.append(try gzip(payload))
        return result
    }
    private static func varint(_ value: Int) -> Data {
        var n = UInt64(value), bytes: [UInt8] = []
        while n >= 128 { bytes.append(UInt8(n & 127) | 128); n >>= 7 }
        bytes.append(UInt8(n)); return Data(bytes)
    }
    private static func gzip(_ input: Data) throws -> Data {
        var stream = z_stream()
        guard deflateInit2_(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS + 16, MAX_MEM_LEVEL,
                            Z_DEFAULT_STRATEGY, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            throw CascadeError("Не удалось создать переносимый профиль.")
        }
        defer { deflateEnd(&stream) }
        var output = Data(count: Int(deflateBound(&stream, uLong(input.count))))
        let status: Int32 = input.withUnsafeBytes { src in
            output.withUnsafeMutableBytes { dst in
                stream.next_in = UnsafeMutablePointer(mutating: src.bindMemory(to: Bytef.self).baseAddress)
                stream.avail_in = uInt(src.count)
                stream.next_out = dst.bindMemory(to: Bytef.self).baseAddress
                stream.avail_out = uInt(dst.count)
                return deflate(&stream, Z_FINISH)
            }
        }
        guard status == Z_STREAM_END else { throw CascadeError("Не удалось сжать профиль.") }
        return output.prefix(Int(stream.total_out))
    }
}
