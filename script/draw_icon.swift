import AppKit
import Foundation

let root = URL(fileURLWithPath: CommandLine.arguments[1])
let iconset = root.appendingPathComponent("work/Cascade.iconset")
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
try FileManager.default.createDirectory(at: root.appendingPathComponent("design"), withIntermediateDirectories: true)
func color(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> NSColor { NSColor(srgbRed:r, green:g, blue:b, alpha:a) }
func draw(_ size: Int) throws -> Data {
    let bitmap = NSBitmapImageRep(bitmapDataPlanes:nil, pixelsWide:size, pixelsHigh:size, bitsPerSample:8, samplesPerPixel:4, hasAlpha:true, isPlanar:false, colorSpaceName:.deviceRGB, bytesPerRow:0, bitsPerPixel:0)!
    let context = NSGraphicsContext(bitmapImageRep: bitmap)!
    NSGraphicsContext.saveGraphicsState(); NSGraphicsContext.current = context
    let cg = context.cgContext
    cg.scaleBy(x:CGFloat(size)/1024, y:CGFloat(size)/1024)
    let tile = NSBezierPath(roundedRect:NSRect(x:64,y:64,width:896,height:896), xRadius:204, yRadius:204)
    cg.saveGState(); cg.setShadow(offset: CGSize(width:0,height:-10), blur:24, color: NSColor.black.withAlphaComponent(0.2).cgColor)
    color(0.045,0.075,0.087).setFill(); tile.fill(); cg.restoreGState()
    cg.saveGState(); tile.addClip()
    NSGradient(starting:color(0.095,0.145,0.16), ending:color(0.025,0.055,0.065))!.draw(in:NSRect(x:64,y:64,width:896,height:896), angle:270)
    let light = NSGradient(starting:color(0.24,0.69,0.56,0.13), ending:color(0.04,0.08,0.08,0))!
    light.draw(fromCenter:NSPoint(x:512,y:470), radius:0, toCenter:NSPoint(x:512,y:470), radius:480, options:[])
    cg.restoreGState()
    color(0.58,0.85,0.80,0.16).setStroke(); tile.lineWidth=2; tile.stroke()
    let top = NSPoint(x:300,y:650), right = NSPoint(x:724,y:650), bottom = NSPoint(x:512,y:306)
    let mint = color(0.52,0.95,0.78)
    let links = NSBezierPath()
    links.move(to:top); links.line(to:right); links.line(to:bottom); links.close()
    links.lineWidth=18; links.lineCapStyle = .round
    let dash: [CGFloat] = [0.1,43]
    links.setLineDash(dash,count:2,phase:0)
    mint.withAlphaComponent(0.8).setStroke(); links.stroke()
    for p in [top,right,bottom] {
        let circle = NSBezierPath(ovalIn:NSRect(x:p.x-62,y:p.y-62,width:124,height:124))
        color(0.055,0.10,0.11).setFill(); circle.fill()
        cg.saveGState(); cg.setShadow(offset:.zero,blur:15,color:mint.withAlphaComponent(0.2).cgColor)
        circle.lineWidth=22; mint.setStroke(); circle.stroke(); cg.restoreGState()
        let highlight = NSBezierPath(ovalIn:NSRect(x:p.x-49,y:p.y-49,width:98,height:98))
        highlight.lineWidth=2; color(0.80,1,0.93,0.22).setStroke(); highlight.stroke()
    }
    NSGraphicsContext.restoreGraphicsState()
    return bitmap.representation(using:.png, properties:[:])!
}
for (name,size) in [("icon_16x16.png",16),("icon_16x16@2x.png",32),("icon_32x32.png",32),("icon_32x32@2x.png",64),("icon_128x128.png",128),("icon_128x128@2x.png",256),("icon_256x256.png",256),("icon_256x256@2x.png",512),("icon_512x512.png",512),("icon_512x512@2x.png",1024)] {
    try draw(size).write(to:iconset.appendingPathComponent(name))
}
try draw(1024).write(to:root.appendingPathComponent("design/Cascade-icon.png"))
print("Rendered 10 icon sizes and 1024px preview")
