import XCTest
import Foundation
@testable import CascadeCore

final class SecurityTests: XCTestCase {
    func testPrivatePayloadRoundTripAndShellSyntax() async throws {
        let secret="a'\n$(touch /tmp/not-allowed)"
        var server=Server(); server.host="2001:db8::1"; server.user="admin"; server.port="2222"
        let request=ServerSecurity.request(action:"apply",server:server,role:"exit",sources:["203.0.113.1","2001:db8::2"],tx:String(repeating:"a",count:32),options:["publicKey":secret])
        let script=try ServerSecurity.script(request)
        XCTAssertFalse(script.contains(secret))
        let lines=script.split(separator:"\n"); let encoded=lines.first { $0.contains("request.json") }!.split(separator:"'")[3]
        let decoded=try XCTUnwrap(Data(base64Encoded:String(encoded)))
        let payload=try XCTUnwrap(JSONSerialization.jsonObject(with:decoded) as? [String:Any])
        XCTAssertEqual(payload["publicKey"] as? String,secret); XCTAssertEqual(payload["sshPort"] as? Int,2222)
        let result=try await Commands.run("/bin/bash",["-n"],input:script)
        XCTAssertEqual(result.status,0,result.error)
    }
    func testControllerResourceIsBundledAndCompiles() async throws {
        let source=try ServerSecurity.controller
        XCTAssertTrue(source.contains("def main(q):"))
        let dir=try PrivateFiles.directory(); defer { try? FileManager.default.removeItem(at:dir) }
        let file=dir.appendingPathComponent("security.py"); try PrivateFiles.write(Data(source.utf8),to:file)
        let r=try await Commands.run("/usr/bin/python3",["-c","import ast,sys; ast.parse(open(sys.argv[1]).read())",file.path])
        XCTAssertEqual(r.status,0,r.error)
    }
}
