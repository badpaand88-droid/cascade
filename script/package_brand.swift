import AppKit
import Foundation
let root=URL(fileURLWithPath:CommandLine.arguments[1])
let image=NSImage(contentsOf:root.appendingPathComponent("design/Cascade-brand.png"))!
let iconset=root.appendingPathComponent("work/Cascade-0.5.iconset")
try FileManager.default.createDirectory(at:iconset,withIntermediateDirectories:true)
for (name,size) in [("icon_16x16.png",16),("icon_16x16@2x.png",32),("icon_32x32.png",32),("icon_32x32@2x.png",64),("icon_128x128.png",128),("icon_128x128@2x.png",256),("icon_256x256.png",256),("icon_256x256@2x.png",512),("icon_512x512.png",512),("icon_512x512@2x.png",1024)] {
 let bitmap=NSBitmapImageRep(bitmapDataPlanes:nil,pixelsWide:size,pixelsHigh:size,bitsPerSample:8,samplesPerPixel:4,hasAlpha:true,isPlanar:false,colorSpaceName:.deviceRGB,bytesPerRow:0,bitsPerPixel:0)!
 NSGraphicsContext.saveGraphicsState(); NSGraphicsContext.current=NSGraphicsContext(bitmapImageRep:bitmap); NSGraphicsContext.current!.imageInterpolation = .none
 image.draw(in:NSRect(x:0,y:0,width:size,height:size),from:.zero,operation:.copy,fraction:1)
 NSGraphicsContext.restoreGraphicsState()
 let png=bitmap.representation(using:.png,properties:[:])!; try png.write(to:iconset.appendingPathComponent(name))
 if size==256 && name=="icon_256x256.png" { try png.write(to:root.appendingPathComponent("work/icon-win-256.png")) }
}
