Option Explicit

Dim fso, shell, dir, config, bin, command, exitCode

Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

dir = fso.GetParentFolderName(WScript.ScriptFullName)
shell.CurrentDirectory = dir

If WScript.Arguments.Count > 0 Then
  config = WScript.Arguments(0)
ElseIf fso.FileExists(fso.BuildPath(dir, "relay-config.local.json")) Then
  config = "relay-config.local.json"
Else
  config = "relay-config.json"
End If

bin = fso.BuildPath(dir, "mycodex-relay.exe")
If Not fso.FileExists(bin) Then
  WScript.Quit 1
End If

If Not fso.FileExists(fso.BuildPath(dir, config)) Then
  command = """" & bin & """ configure --config """ & config & """ --state relay-state.db"
  exitCode = shell.Run(command, 0, True)
  If exitCode <> 0 Then
    WScript.Quit exitCode
  End If
End If

command = "cmd /c """"" & bin & """ serve --config """ & config & """ >> relay.out.log 2>> relay.err.log"""
shell.Run command, 0, False
WScript.Quit 0
