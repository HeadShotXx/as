unit UnitRemoteShell;

interface

uses
  Winapi.Windows, Winapi.Messages,
  System.SysUtils, System.Variants, System.Classes, System.JSON,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls,
  ncLines;

type
  TRemoteShellSendJSONEvent = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TRemoteShellFormClosedEvent = procedure(aLine: TncLine) of object;

  TForm5 = class(TForm)
    Memo1: TMemo;
    Edit1: TEdit;
    procedure Edit1KeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
    procedure FormShow(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
  private
    FLine         : TncLine;
    FClientID     : string;
    FOnSendJSON   : TRemoteShellSendJSONEvent;
    FOnFormClosed : TRemoteShellFormClosedEvent;
    FStarted      : Boolean;

    procedure AppendConsole(const AText: string);
    procedure SendShellCommand(const AAction: string; const ACommand: string = '');
  public
    destructor Destroy; override;

    procedure SetupForClient(aLine: TncLine; const AClientID: string;
      ASendJSON: TRemoteShellSendJSONEvent; AFormClosed: TRemoteShellFormClosedEvent);
    procedure DetachCallbacks;
    procedure RequestShellStart;
    procedure HandleShellJSON(JSONObj: TJSONObject);
  end;

var
  Form5: TForm5;

implementation

{$R *.dfm}

{ TForm5 }

destructor TForm5.Destroy;
begin
  if Assigned(FOnSendJSON) and Assigned(FLine) then
    SendShellCommand('shellstop');

  if Assigned(FOnFormClosed) and Assigned(FLine) then
    FOnFormClosed(FLine);
  DetachCallbacks;

  inherited;
end;

procedure TForm5.DetachCallbacks;
begin
  FOnSendJSON   := nil;
  FOnFormClosed := nil;
end;

procedure TForm5.SetupForClient(aLine: TncLine; const AClientID: string;
  ASendJSON: TRemoteShellSendJSONEvent; AFormClosed: TRemoteShellFormClosedEvent);
begin
  FLine         := aLine;
  FClientID     := AClientID;
  FOnSendJSON   := ASendJSON;
  FOnFormClosed := AFormClosed;
  FStarted      := False;

  Caption := 'Remote Shell - ' + FClientID;

  Memo1.ReadOnly   := True;
  Memo1.ScrollBars := ssBoth;
  Memo1.WordWrap   := False;
  Memo1.Clear;

  Edit1.Text := '';
  Edit1.OnKeyDown := Edit1KeyDown;
  OnShow := FormShow;
  OnClose := FormClose;

  AppendConsole('Remote shell hazirlaniyor...');
end;

procedure TForm5.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if Assigned(FOnSendJSON) and Assigned(FLine) then
    SendShellCommand('shellstop');

  if Assigned(FOnFormClosed) and Assigned(FLine) then
    FOnFormClosed(FLine);

  DetachCallbacks;
  if Form5 = Self then
    Form5 := nil;

  Action := caFree;
end;

procedure TForm5.FormShow(Sender: TObject);
begin
  if Edit1.CanFocus then
    Edit1.SetFocus;
end;

procedure TForm5.AppendConsole(const AText: string);
var
  TextToAppend: string;
begin
  if AText = '' then
    Exit;

  TextToAppend := AText;
  if (Copy(TextToAppend, Length(TextToAppend), 1) <> #10) and
     (Copy(TextToAppend, Length(TextToAppend), 1) <> #13) then
    TextToAppend := TextToAppend + sLineBreak;

  Memo1.SelStart := Length(Memo1.Text);
  Memo1.SelText  := TextToAppend;
  Memo1.Perform(EM_SCROLLCARET, 0, 0);
end;

procedure TForm5.SendShellCommand(const AAction: string; const ACommand: string);
var
  JSONObj: TJSONObject;
begin
  if not Assigned(FLine) or not Assigned(FOnSendJSON) then
    Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', AAction);

    if ACommand <> '' then
      JSONObj.AddPair('command', ACommand);

    FOnSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm5.RequestShellStart;
begin
  if FStarted then
    Exit;

  FStarted := True;
  SendShellCommand('shellstart');
end;

procedure TForm5.Edit1KeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
var
  CommandText: string;
begin
  if Key <> VK_RETURN then
    Exit;

  Key := 0;
  CommandText := Trim(Edit1.Text);
  if CommandText = '' then
    Exit;

  AppendConsole('> ' + CommandText);
  Edit1.Clear;
  SendShellCommand('shellcommand', CommandText);
end;

procedure TForm5.HandleShellJSON(JSONObj: TJSONObject);
var
  OutputVal : TJSONValue;
  ErrorVal  : TJSONValue;
  StatusVal : TJSONValue;
begin
  if JSONObj = nil then
    Exit;

  StatusVal := JSONObj.Values['status'];
  if Assigned(StatusVal) and SameText(StatusVal.Value, 'started') then
    AppendConsole('Remote shell hazir.');

  OutputVal := JSONObj.Values['output'];
  if Assigned(OutputVal) and (OutputVal.Value <> '') then
    AppendConsole(OutputVal.Value);

  ErrorVal := JSONObj.Values['error'];
  if Assigned(ErrorVal) and (ErrorVal.Value <> '') then
    AppendConsole(ErrorVal.Value);
end;

end.


