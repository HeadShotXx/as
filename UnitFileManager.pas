unit UnitFileManager;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls, Vcl.ExtCtrls,
  Vcl.Menus, System.JSON, ncLines, System.NetEncoding;

type
  TSendJSONProc = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TUnregisterProc = procedure(aLine: TncLine) of object;

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
    procedure GeriClick(Sender: TObject);
    procedure YenileClick(Sender: TObject);
    procedure Edit1KeyPress(Sender: TObject; var Key: Char);
    procedure ListView1DblClick(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
  private
    FLine: TncLine;
    FClientID: string;
    FOnSendJSON: TSendJSONProc;
    FOnUnregister: TUnregisterProc;
    FCurrentPath: string;
    FLastPath: string;
    FClipboardPath: string;
    FClipboardMode: string; // 'copy' or 'cut'
  public
    procedure SetupForClient(aLine: TncLine; const ClientID: string;
      SendJSONProc: TSendJSONProc; UnregisterProc: TUnregisterProc);
    procedure DetachCallbacks;
    procedure HandleFileManagerJSON(JSONObj: TJSONObject);
    procedure RequestFiles(const Path: string);
    procedure Refresh;
  end;

var
  Form9: TForm9;

implementation

{$R *.dfm}

procedure TForm9.SetupForClient(aLine: TncLine; const ClientID: string;
  SendJSONProc: TSendJSONProc; UnregisterProc: TUnregisterProc);
begin
  FLine := aLine;
  FClientID := ClientID;
  FOnSendJSON := SendJSONProc;
  FOnUnregister := UnregisterProc;
  Caption := 'File Manager - ' + ClientID;
  FCurrentPath := '';
  FClipboardPath := '';

  ListView1.Items.Clear;
  Edit1.Text := '';
  OnClose := FormClose;
  Geri.OnClick := GeriClick;
  Yenile.OnClick := YenileClick;
  Edit1.OnKeyPress := Edit1KeyPress;
  ListView1.OnDblClick := ListView1DblClick;
end;

procedure TForm9.DetachCallbacks;
begin
  FLine := nil;
  FOnSendJSON := nil;
  FOnUnregister := nil;
end;

procedure TForm9.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if Assigned(FOnUnregister) then
    FOnUnregister(FLine);
  Action := caFree;
end;

procedure TForm9.RequestFiles(const Path: string);
var
  JSONObj: TJSONObject;
begin
  if not Assigned(FOnSendJSON) then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'filemanager_list');
    JSONObj.AddPair('path', Path);
    FOnSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
  StatusBar1.SimpleText := 'Requesting directory: ' + Path;
end;

procedure TForm9.Refresh;
begin
  RequestFiles(FCurrentPath);
end;

procedure TForm9.HandleFileManagerJSON(JSONObj: TJSONObject);
var
  Items: TJSONArray;
  i: Integer;
  JSONItem: TJSONValue;
  ListItem: TListItem;
  FolderCount, FileCount: Integer;
  Action: string;
  Status: string;
  Msg: string;
  Data64: string;
  Bytes: TBytes;
  SaveDlg: TSaveDialog;
  FS: TFileStream;
begin
  if not Assigned(JSONObj) then Exit;

  Action := JSONObj.GetValue<string>('action', '');
  if Action = 'filemanager_list' then
  begin
    FCurrentPath := JSONObj.GetValue<string>('path', '');
    Edit1.Text := FCurrentPath;

    ListView1.Items.BeginUpdate;
    FolderCount := 0;
    FileCount := 0;
    try
      ListView1.Items.Clear;
      Items := JSONObj.GetValue<TJSONArray>('items');
      if Assigned(Items) then
      begin
        for i := 0 to Items.Count - 1 do
        begin
          JSONItem := Items.Items[i];
          ListItem := ListView1.Items.Add;
          ListItem.Caption := JSONItem.GetValue<string>('name', '');
          ListItem.SubItems.Add(JSONItem.GetValue<string>('date', ''));
          var ItemType := JSONItem.GetValue<string>('type', '');
          ListItem.SubItems.Add(ItemType);
          ListItem.SubItems.Add(JSONItem.GetValue<string>('size', ''));

          if SameText(ItemType, 'Directory') or SameText(ItemType, 'Drive') then
            Inc(FolderCount)
          else
            Inc(FileCount);
        end;
      end;
    finally
      ListView1.Items.EndUpdate;
    end;
    StatusBar1.SimpleText := Format('Folders [%d] Files [%d] listed.', [FolderCount, FileCount]);
  end
  else if Action = 'filemanager_download' then
  begin
    Status := JSONObj.GetValue<string>('status', '');
    if Status = 'success' then
    begin
      Data64 := JSONObj.GetValue<string>('data', '');
      Bytes := TNetEncoding.Base64.DecodeStringToBytes(Data64);

      SaveDlg := TSaveDialog.Create(nil);
      try
        SaveDlg.FileName := JSONObj.GetValue<string>('name', 'downloaded_file');
        if SaveDlg.Execute then
        begin
          FS := TFileStream.Create(SaveDlg.FileName, fmCreate);
          try
            if Length(Bytes) > 0 then
              FS.WriteBuffer(Bytes[0], Length(Bytes));
            StatusBar1.SimpleText := 'File saved: ' + SaveDlg.FileName;
          finally
            FS.Free;
          end;
        end;
      finally
        SaveDlg.Free;
      end;
    end
    else
    begin
      Msg := JSONObj.GetValue<string>('message', 'Unknown error');
      StatusBar1.SimpleText := 'Download failed: ' + Msg;
    end;
  end
  else
  begin
    Status := JSONObj.GetValue<string>('status', '');
    Msg := JSONObj.GetValue<string>('message', '');
    if Status = 'success' then
    begin
      StatusBar1.SimpleText := Msg;
      Refresh;
    end
    else
    begin
      StatusBar1.SimpleText := 'Error: ' + Msg;
    end;
  end;
end;

procedure TForm9.GeriClick(Sender: TObject);
var
  Path: string;
  P: Integer;
begin
  Path := FCurrentPath;
  if (Path = '') or (Path = '\') then Exit;

  if Path[Length(Path)] = '\' then
    Delete(Path, Length(Path), 1);

  P := LastDelimiter('\', Path);
  if P > 0 then
    Path := Copy(Path, 1, P)
  else
    Path := '';

  RequestFiles(Path);
end;

procedure TForm9.YenileClick(Sender: TObject);
begin
  Refresh;
end;

procedure TForm9.Edit1KeyPress(Sender: TObject; var Key: Char);
begin
  if Key = #13 then
  begin
    Key := #0;
    RequestFiles(Edit1.Text);
  end;
end;

procedure TForm9.ListView1DblClick(Sender: TObject);
var
  Item: TListItem;
  NewPath: string;
begin
  Item := ListView1.Selected;
  if Item = nil then Exit;

  if Item.SubItems[1] = 'Directory' then
  begin
    NewPath := FCurrentPath;
    if (NewPath <> '') and (NewPath[Length(NewPath)] <> '\') then
      NewPath := NewPath + '\';
    NewPath := NewPath + Item.Caption;
    RequestFiles(NewPath);
  end;
end;

procedure TForm9.Copy1Click(Sender: TObject);
var
  Item: TListItem;
begin
  Item := ListView1.Selected;
  if Item = nil then Exit;

  FClipboardPath := FCurrentPath;
  if (FClipboardPath <> '') and (FClipboardPath[Length(FClipboardPath)] <> '\') then
    FClipboardPath := FClipboardPath + '\';
  FClipboardPath := FClipboardPath + Item.Caption;
  FClipboardMode := 'copy';
  StatusBar1.SimpleText := 'Copied to clipboard: ' + Item.Caption;
end;

procedure TForm9.Delete1Click(Sender: TObject);
var
  Item: TListItem;
  JSONObj: TJSONObject;
begin
  Item := ListView1.Selected;
  if Item = nil then Exit;

  if MessageBox(Handle, PChar('Are you sure you want to delete "' + Item.Caption + '"?'),
    'Delete', MB_YESNO or MB_ICONQUESTION) <> IDYES then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'filemanager_delete');
    JSONObj.AddPair('path', FCurrentPath);
    JSONObj.AddPair('name', Item.Caption);
    FOnSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm9.Download1Click(Sender: TObject);
var
  Item: TListItem;
  JSONObj: TJSONObject;
begin
  Item := ListView1.Selected;
  if Item = nil then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'filemanager_download');
    JSONObj.AddPair('path', FCurrentPath);
    JSONObj.AddPair('name', Item.Caption);
    FOnSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
  StatusBar1.SimpleText := 'Downloading: ' + Item.Caption;
end;

procedure TForm9.NewFolder1Click(Sender: TObject);
var
  FolderName: string;
  JSONObj: TJSONObject;
begin
  FolderName := InputBox('New Folder', 'Enter folder name:', 'New Folder');
  if (FolderName = '') or (FolderName = 'New Folder') then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'filemanager_newfolder');
    JSONObj.AddPair('path', FCurrentPath);
    JSONObj.AddPair('name', FolderName);
    FOnSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm9.Normal1Click(Sender: TObject);
var
  Item: TListItem;
  JSONObj: TJSONObject;
begin
  Item := ListView1.Selected;
  if Item = nil then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'filemanager_execute');
    JSONObj.AddPair('path', FCurrentPath);
    JSONObj.AddPair('name', Item.Caption);
    JSONObj.AddPair('mode', 'normal');
    FOnSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm9.Normal2Click(Sender: TObject);
var
  Item: TListItem;
  JSONObj: TJSONObject;
begin
  Item := ListView1.Selected;
  if Item = nil then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'filemanager_execute');
    JSONObj.AddPair('path', FCurrentPath);
    JSONObj.AddPair('name', Item.Caption);
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
  if FClipboardPath = '' then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'filemanager_paste');
    JSONObj.AddPair('src', FClipboardPath);
    JSONObj.AddPair('dest_path', FCurrentPath);
    JSONObj.AddPair('mode', FClipboardMode);
    FOnSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
  StatusBar1.SimpleText := 'Pasting: ' + FClipboardPath;
end;

procedure TForm9.Rename1Click(Sender: TObject);
var
  Item: TListItem;
  NewName: string;
  JSONObj: TJSONObject;
begin
  Item := ListView1.Selected;
  if Item = nil then Exit;

  NewName := InputBox('Rename', 'Enter new name:', Item.Caption);
  if (NewName = '') or (NewName = Item.Caption) then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'filemanager_rename');
    JSONObj.AddPair('path', FCurrentPath);
    JSONObj.AddPair('oldname', Item.Caption);
    JSONObj.AddPair('newname', NewName);
    FOnSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm9.RunAs1Click(Sender: TObject);
var
  Item: TListItem;
  JSONObj: TJSONObject;
begin
  Item := ListView1.Selected;
  if Item = nil then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'filemanager_execute');
    JSONObj.AddPair('path', FCurrentPath);
    JSONObj.AddPair('name', Item.Caption);
    JSONObj.AddPair('mode', 'runas');
    FOnSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm9.Upload1Click(Sender: TObject);
var
  OpenDlg: TOpenDialog;
  FS: TFileStream;
  Bytes: TBytes;
  JSONObj: TJSONObject;
  Base64: string;
  FileName: string;
begin
  OpenDlg := TOpenDialog.Create(nil);
  try
    if OpenDlg.Execute then
    begin
      FileName := ExtractFileName(OpenDlg.FileName);
      FS := TFileStream.Create(OpenDlg.FileName, fmOpenRead or fmShareDenyWrite);
      try
        SetLength(Bytes, FS.Size);
        if FS.Size > 0 then
          FS.ReadBuffer(Bytes[0], FS.Size);

        JSONObj := TJSONObject.Create;
        try
          JSONObj.AddPair('action', 'filemanager_upload');
          JSONObj.AddPair('path', FCurrentPath);
          JSONObj.AddPair('name', FileName);
          // For simplicity in this implementation, we send as one block.
          // For very large files, chunking would be needed.
          JSONObj.AddPair('data', TNetEncoding.Base64.EncodeBytesToString(Bytes));
          FOnSendJSON(FLine, JSONObj);
        finally
          JSONObj.Free;
        end;
        StatusBar1.SimpleText := 'Uploading: ' + FileName;
      finally
        FS.Free;
      end;
    end;
  finally
    OpenDlg.Free;
  end;
end;

end.
