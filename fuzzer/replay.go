// Copyright 2015 Yahoo Inc.
// Licensed under the BSD license, see LICENSE file for terms.
// Written by Stuart Larsen
// http2fuzz - HTTP/2 Fuzzer
package fuzzer

import "github.com/c0nrad/http2fuzz/util"
import "github.com/bradfitz/http2"
import "os"
import "fmt"
import "time"

var ReplayWriteFile *os.File

func init() {
	ReplayWriteFile = OpenWriteFile("logs/"+time.Now().Format(time.RFC3339)+"_replay.json")
}

type ReplayHandler struct {
	ReplayFile *os.File
}

func OpenWriteFile(filename string) *os.File {
	f, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	return f
}

func TruncateFile() {
	ReplayWriteFile.Truncate(0)
	ReplayWriteFile.Seek(0, 0)
}

func WriteToReplayFile(data []byte) {
	data = append(data, '\n')
	_, err := ReplayWriteFile.Write(data)
	if err != nil {
		panic(err)
	}
	ReplayWriteFile.Sync()
}

func SaveRawFrame(frameType, flags uint8, streamID uint32, payload []byte) {
	frame := map[string]interface{}{
		"FrameMethod": "RawFrame",
		"FrameType":   frameType,
		"Flags":       flags,
		"StreamID":    streamID,
		"Payload":     util.ToBase64(payload),
	}

	out := util.ToJSON(frame)
	WriteToReplayFile(out)
}
 
func SaveResetFrame(streamID uint32, errorCode uint32) {
        frame := map[string]interface{}{
                "FrameMethod": "ResetFrame",
                "StreamID":    streamID,
                "ErrorCode":    errorCode,
        }

        out := util.ToJSON(frame)
	WriteToReplayFile(out)
}

func SaveWindowUpdateFrame(streamId uint32, incr uint32) {
	frame := map[string]interface{}{
                "FrameMethod": "WindowUpdateFrame",
                "StreamID":    streamId,
                "Incr":    incr,
        }
	        out := util.ToJSON(frame)
        WriteToReplayFile(out)
}

func SavePriorityFrame(streamId, streamDep uint32, weight uint8, exclusive bool) {
        frame := map[string]interface{}{
                "FrameMethod": "PriorityFrame",
                "StreamID":    streamId,
                "StreamDep":    streamDep,
		"Weight":	weight,
		"Exclusive":	exclusive,
        }
        out := util.ToJSON(frame)
        WriteToReplayFile(out)
}

func SaveDataFrame(streamID uint32, endStream bool, data []byte){
       frame := map[string]interface{}{
                "FrameMethod": "DataFrame",
                "StreamID":    streamID,
		"EndStream": endStream,
		"Data":	util.ToBase64(data),
        }
        out := util.ToJSON(frame)
        WriteToReplayFile(out)
}

func SavePushPromiseFrame(streamID uint32, promiseID uint32, blockFragment []byte, endHeaders bool, padLength uint8){
	frame := map[string]interface{}{
                "FrameMethod" : "PushPromiseFrame",
		"StreamID" : streamID,
                "PromiseID" : promiseID,
                "BlockFragment" : blockFragment,
                "EndHeaders" : endHeaders,
                "PadLength" : padLength,
        }
        out := util.ToJSON(frame)
        WriteToReplayFile(out)
}
func SaveSettingsFrame(settings []http2.Setting){
       frame := map[string]interface{}{
                "FrameMethod": "SettingsFrame",
                "Settings":    settings,
        }
        out := util.ToJSON(frame)
        WriteToReplayFile(out)
}

func SavePing(data [8]byte){
       frame := map[string]interface{}{
                "FrameMethod": "Ping",
                "Data":    data,
        }
        out := util.ToJSON(frame)
        WriteToReplayFile(out)
}

func SaveContinuationFrame(streamID uint32, endStream bool, data []byte) {
        frame := map[string]interface{}{
                "FrameMethod": "ContinuationFrame",
                "StreamID":    streamID,
                "EndStream":    endStream,
                "Data":       util.ToBase64(data),
        }
        out := util.ToJSON(frame)
        WriteToReplayFile(out)
}

func isNil(a interface{}) bool {
  defer func() { recover() }()
  return a == nil 
}

func RunReplay(c *Connection, filename string) {
	frames := util.ReadLines(filename)
 	for _, frameJSON := range frames {
 		frame := util.FromJSON([]byte(frameJSON))

 		if c.Err != nil {
 			fmt.Println("Connection Error", c.Err, "restarting connection")
 			c = NewConnection(c.Host, c.IsTLS, c.IsPreface, c.IsSendSettings)
 		}
		switch frame["FrameMethod"] {

		case "RawFrame":
 			frameType := uint8(frame["FrameType"].(float64))
 			flags := uint8(frame["Flags"].(float64))
 			streamID := uint32(frame["StreamID"].(float64))
 			payload := util.FromBase64(frame["Payload"].(string))
 			c.WriteRawFrame(frameType, flags, streamID, payload)
 		case "Ping":
			pingData := frame["Data"].([]interface{})
			var pingDataArray [8]byte
			for i:= 0; i < len(pingData); i++ {
				pingDataArray[i] = uint8(pingData[i].(float64))
			}
			
			c.SendPing(pingDataArray)
		case "SettingsFrame":
			arrSettings := frame["Settings"].([]interface{})
			settings := make([]http2.Setting, len(arrSettings))
			for i := 0; i < len(arrSettings); i++ {
				singleSettingsInterface := arrSettings[i].(map[string]interface{})
				http2Setting := http2.Setting{http2.SettingID(singleSettingsInterface["ID"].(float64)), uint32(singleSettingsInterface["Val"].(float64))}
				settings[i] = http2Setting
			}
			c.WriteSettingsFrame(settings)
		case "DataFrame":
			streamID := uint32(frame["StreamID"].(float64))
			endStream := bool(frame["EndStream"].(bool))
			data := util.FromBase64(frame["Data"].(string))
			c.WriteDataFrame(streamID, endStream, data)
		case "PushPromiseFrame":
			streamID := uint32(frame["StreamID"].(float64))
                        promiseID := uint32(frame["PromiseID"].(float64))
                        blockFragment := util.FromBase64(frame["BlockFragment"].(string))
                        endHeaders := frame["EndHeaders"].(bool)                                
			padLength := uint8 (frame["PadLength"].(float64)) 
			promise := http2.PushPromiseParam{streamID, promiseID, blockFragment, endHeaders, padLength}
			c.WritePushPromiseFrame(promise)
		case "ContinuationFrame":
			streamID := uint32(frame["StreamID"].(float64))
			endStream := frame["EndStream"].(bool)
			data := util.FromBase64(frame["Data"].(string))
			c.WriteContinuationFrame(streamID, endStream, data)
		case "PriorityFrame":
			streamID := uint32(frame["StreamID"].(float64))
			streamDep := uint32(frame["StreamDep"].(float64))
			weight := uint8(frame["Weight"].(float64))
			exclusive := frame["Exclusive"].(bool)
			c.WritePriorityFrame(streamID, streamDep, weight, exclusive)
		case "ResetFrame":
			streamID := uint32(frame["StreamID"].(float64))
			errorCode := uint32(frame["ErrorCode"].(float64))
			c.WriteResetFrame(streamID, errorCode)
			c = NewConnection(c.Host, c.IsTLS, c.IsPreface, c.IsSendSettings)
		case "WindowUpdateFrame":
			streamID := uint32(frame["StreamID"].(float64))
			incr := uint32(frame["Incr"].(float64))
			c.WriteWindowUpdateFrame(streamID, incr)
		}
 	}
 	fmt.Println("ALL DONE")
 }
