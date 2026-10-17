Option Explicit

Dim fso, shell, dir, config, statePath, bin, command, exitCode

Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

dir = fso.GetParentFolderName(WScript.ScriptFullName)
shell.CurrentDirectory = dir

If WScript.Arguments.Count > 0 Then
  config = WScript.Arguments(0)
  statePath = fso.GetBaseName(config) & ".db"
ElseIf fso.FileExists(fso.BuildPath(dir, "relay-config.local.json")) Then
  config = "relay-config.local.json"
  statePath = "relay-state.db"
Else
  config = "relay-config.json"
  statePath = "relay-state.db"
End If

If WScript.Arguments.Count > 1 Then
  statePath = WScript.Arguments(1)
End If

bin = fso.BuildPath(dir, "mycodex-relay.exe")
If Not fso.FileExists(bin) Then
  WScript.Quit 1
End If

If Not fso.FileExists(fso.BuildPath(dir, config)) Then
  command = """" & bin & """ local init --config """ & config & """ --state """ & statePath & """ --json"
  exitCode = shell.Run(command, 0, True)
  If exitCode <> 0 Then
    WScript.Quit exitCode
  End If
End If

command = "cmd /c """"" & bin & """ serve --config """ & config & """ >> relay.out.log 2>> relay.err.log"""
shell.Run command, 0, False
WScript.Quit 0
