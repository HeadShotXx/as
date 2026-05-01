unit UnitProcessManager;

interface

uses
  Winapi.Windows, Winapi.Messages,
  System.SysUtils, System.Variants, System.Classes, System.JSON,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.ComCtrls, Vcl.Menus,
  ncLines;

type
  TProcessSendJSONEvent = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TProcessFormClosedEvent = procedure(aLine: TncLine) of object;

  TForm4 = class(TForm)
    ListView1: TListView;
    StatusBar1: TStatusBar;
    PopupMenu1: TPopupMenu;
    KillProcess1: TMenuItem;
    RestartProcess1: TMenuItem;
    RefreshTasks1: TMenuItem;
    procedure RefreshTasks1Click(Sender: TObject);
    procedure KillProcess1Click(Sender: TObject);
    procedure RestartProcess1Click(Sender: TObject);
  private
    FLine         : TncLine;
    FClientID     : string;
    FOnSendJSON   : TProcessSendJSONEvent;
    FOnFormClosed : TProcessFormClosedEvent;

    function  SelectedPID(out APID: Integer): Boolean;
    function  SelectedProcessName: string;
    procedure SendProcessCommand(const AAction: string; APID: Integer = 0;
                                 const AProcessName: string = '');
    procedure UpdateStatusBar;
    procedure EnsureListViewColumns;
  protected
    procedure DoClose(var Action: TCloseAction); override;
  public
    destructor Destroy; override;

    procedure SetupForClient(aLine: TncLine; const AClientID: string;
      ASendJSON: TProcessSendJSONEvent; AFormClosed: TProcessFormClosedEvent);
    procedure DetachCallbacks;
    procedure RequestProcesses;
    procedure HandleProcessJSON(JSONObj: TJSONObject);
  end;

var
  Form4: TForm4;

implementation

{$R *.dfm}

{ TForm4 }

destructor TForm4.Destroy;
begin
  if Assigned(FOnFormClosed) and Assigned(FLine) then
    FOnFormClosed(FLine);
  inherited;
end;

procedure TForm4.DetachCallbacks;
begin
  FOnSendJSON   := nil;
  FOnFormClosed := nil;
end;

procedure TForm4.DoClose(var Action: TCloseAction);
begin
  inherited;
  Action := caFree;
end;

procedure TForm4.EnsureListViewColumns;
begin
  ListView1.ViewStyle := vsReport;
  ListView1.ReadOnly  := True;
  ListView1.RowSelect := True;

  if ListView1.Columns.Count = 0 then
  begin
    with ListView1.Columns.Add do
    begin
      Caption := 'Name';
      Width   := 260;
    end;

    with ListView1.Columns.Add do
    begin
      Caption := 'PID';
      Width   := 90;
    end;
  end;
end;

procedure TForm4.SetupForClient(aLine: TncLine; const AClientID: string;
  ASendJSON: TProcessSendJSONEvent; AFormClosed: TProcessFormClosedEvent);
begin
  FLine         := aLine;
  FClientID     := AClientID;
  FOnSendJSON   := ASendJSON;
  FOnFormClosed := AFormClosed;

  Caption := 'Process Manager - ' + FClientID;
  EnsureListViewColumns;
  UpdateStatusBar;
end;

procedure TForm4.UpdateStatusBar;
var
  Text: string;
begin
  Text := 'Process [' + IntToStr(ListView1.Items.Count) + ']';

  if StatusBar1.Panels.Count > 0 then
    StatusBar1.Panels[0].Text := Text
  else
    StatusBar1.SimpleText := Text;
end;

function TForm4.SelectedPID(out APID: Integer): Boolean;
var
  PIDText: string;
begin
  Result := False;
  APID   := 0;

  if ListView1.Selected = nil then
    Exit;

  if ListView1.Selected.SubItems.Count = 0 then
    Exit;

  PIDText := Trim(ListView1.Selected.SubItems[0]);
  Result  := TryStrToInt(PIDText, APID);
end;

function TForm4.SelectedProcessName: string;
begin
  Result := '';
  if ListView1.Selected <> nil then
    Result := ListView1.Selected.Caption;
end;

procedure TForm4.SendProcessCommand(const AAction: string; APID: Integer;
  const AProcessName: string);
var
  JSONObj: TJSONObject;
begin
  if not Assigned(FLine) or not Assigned(FOnSendJSON) then
    Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', AAction);

    if APID > 0 then
      JSONObj.AddPair('pid', TJSONNumber.Create(APID));

    if AProcessName <> '' then
      JSONObj.AddPair('name', AProcessName);

    FOnSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm4.RequestProcesses;
begin
  SendProcessCommand('getprocesses');
end;

procedure TForm4.HandleProcessJSON(JSONObj: TJSONObject);
var
  ProcessesVal : TJSONValue;
  ProcessesArr : TJSONArray;
  ProcVal      : TJSONValue;
  ProcObj      : TJSONObject;
  Item         : TListItem;
  Name         : string;
  PID          : string;
  i            : Integer;
begin
  if JSONObj = nil then
    Exit;

  ProcessesVal := JSONObj.Values['processes'];
  if not (ProcessesVal is TJSONArray) then
    Exit;

  ProcessesArr := TJSONArray(ProcessesVal);

  ListView1.Items.BeginUpdate;
  try
    ListView1.Items.Clear;

    for i := 0 to ProcessesArr.Count - 1 do
    begin
      ProcVal := ProcessesArr.Items[i];
      if not (ProcVal is TJSONObject) then
        Continue;

      ProcObj := TJSONObject(ProcVal);

      Name := '';
      PID  := '';

      if Assigned(ProcObj.Values['name']) then
        Name := ProcObj.Values['name'].Value;
      if Assigned(ProcObj.Values['pid']) then
        PID := ProcObj.Values['pid'].Value;

      Item := ListView1.Items.Add;
      Item.Caption := Name;
      Item.SubItems.Add(PID);
    end;
  finally
    ListView1.Items.EndUpdate;
  end;

  UpdateStatusBar;
end;

procedure TForm4.KillProcess1Click(Sender: TObject);
var
  PID         : Integer;
  ProcessName : string;
begin
  if not SelectedPID(PID) then
    Exit;

  ProcessName := SelectedProcessName;
  if MessageBox(Handle,
                PChar('Seçili process sonlandýrýlsýn mý?' + sLineBreak +
                      ProcessName + ' [' + IntToStr(PID) + ']'),
                'Kill Process',
                MB_YESNO or MB_ICONWARNING) <> IDYES then
    Exit;

  SendProcessCommand('killprocess', PID, ProcessName);
end;

procedure TForm4.RefreshTasks1Click(Sender: TObject);
begin
  RequestProcesses;
end;

procedure TForm4.RestartProcess1Click(Sender: TObject);
var
  PID         : Integer;
  ProcessName : string;
begin
  if not SelectedPID(PID) then
    Exit;

  ProcessName := SelectedProcessName;
  if MessageBox(Handle,
                PChar('Seçili process yeniden baþlatýlsýn mý?' + sLineBreak +
                      ProcessName + ' [' + IntToStr(PID) + ']'),
                'Restart Process',
                MB_YESNO or MB_ICONQUESTION) <> IDYES then
    Exit;

  SendProcessCommand('restartprocess', PID, ProcessName);
end;

end.

