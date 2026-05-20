program NightRAT;

uses
  Vcl.Forms,
  Unit1 in 'Unit1.pas' {Form1},
  Vcl.Themes,
  Vcl.Styles,
  UnitSendMessage in 'UnitSendMessage.pas' {Form2},
  UnitGetInformation in 'UnitGetInformation.pas' {Form3},
  UnitProcessManager in 'UnitProcessManager.pas' {Form4},
  UnitRemoteShell in 'UnitRemoteShell.pas' {Form5},
  UnitRemoteMonitoring in 'UnitRemoteMonitoring.pas' {Form6},
  UnitKeylogger in 'UnitKeylogger.pas' {Form7},
  UnitOpenURL in 'UnitOpenURL.pas' {Form8},
  UnitFileManager in 'UnitFileManager.pas' {Form9},
  UnitHiddenVNC in 'UnitHiddenVNC.pas' {Form10};

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  TStyleManager.TrySetStyle('Glow');
  Application.CreateForm(TForm1, Form1);
  Application.CreateForm(TForm2, Form2);
  Application.CreateForm(TForm3, Form3);
  Application.CreateForm(TForm4, Form4);
  Application.CreateForm(TForm5, Form5);
  Application.CreateForm(TForm6, Form6);
  Application.CreateForm(TForm7, Form7);
  Application.CreateForm(TForm8, Form8);
  Application.CreateForm(TForm9, Form9);
  Application.CreateForm(TForm10, Form10);
  Application.Run;
end.
