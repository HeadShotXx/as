unit UnitStartupManager;

interface

uses
  Winapi.Windows, Winapi.Messages, Winapi.Winsock2, System.SysUtils, System.Variants,
  System.Classes, System.JSON, System.Generics.Collections,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.ComCtrls, Vcl.Menus,
  ncLines;

type
  TSendJSONProc = procedure(aLine: TncLine; JSONObj: TJSONObject) of object;
  TUnregisterProc = procedure(aLine: TncLine) of object;

  TForm12 = class(TForm)
    StatusBar1: TStatusBar;
    ListView1: TListView;
    PopupMenu1: TPopupMenu;
    Refresh1: TMenuItem;
    Delete1: TMenuItem;
    procedure Refresh1Click(Sender: TObject);
    procedure Delete1Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure ListView1MouseDown(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
  private
    FLine       : TncLine;
    FChannelLine: TncLine;
    FClientID   : string;
    FSendJSON   : TSendJSONProc;
    FUnregister : TUnregisterProc;
    function GetActiveLine: TncLine;
    procedure UpdateStatusBar;
  public
    procedure SetChannelLine(aChanLine: TncLine);
    procedure SetupForClient(aLine: TncLine; const AClientID: string;
      ASendJSON: TSendJSONProc; AUnregister: TUnregisterProc);
    procedure HandleStartupJSON(JSONObj: TJSONObject);
    procedure DetachCallbacks;
    procedure RequestStartupList;
  end;

var
  Form12: TForm12;

implementation

{$R *.dfm}

{ ---------------------------------------------------------------------------- }
{  Setup & Lifecycle                                                             }
{ ---------------------------------------------------------------------------- }

function TForm12.GetActiveLine: TncLine;
begin
  if Assigned(FChannelLine) then
    Result := FChannelLine
  else
    Result := FLine;
end;

procedure TForm12.SetChannelLine(aChanLine: TncLine);
begin
  FChannelLine := aChanLine;
end;

procedure TForm12.SetupForClient(aLine: TncLine; const AClientID: string;
  ASendJSON: TSendJSONProc; AUnregister: TUnregisterProc);
begin
  FLine       := aLine;
  FChannelLine := nil;
  FClientID   := AClientID;
  FSendJSON   := ASendJSON;
  FUnregister := AUnregister;
  Caption     := 'Startup Manager  –  ' + AClientID;

  ListView1.PopupMenu := PopupMenu1;
  ListView1.ViewStyle := vsReport;
  ListView1.ReadOnly  := True;
  ListView1.RowSelect := True;

  // Kolonlarý listview'a ekle (eðer yoksa)
  if ListView1.Columns.Count = 0 then
  begin
    with ListView1.Columns.Add do begin Name := 'col_name';  Caption := 'Name';  Width := 200; end;
    with ListView1.Columns.Add do begin Name := 'col_type';  Caption := 'Type';  Width := 130; end;
    with ListView1.Columns.Add do begin Name := 'col_path';  Caption := 'Path';  Width := 400; end;
  end;

  UpdateStatusBar;
  OnClose := FormClose;
end;

procedure TForm12.DetachCallbacks;
begin
  FSendJSON   := nil;
  FUnregister := nil;
  FLine       := nil;
end;

procedure TForm12.FormCreate(Sender: TObject);
begin
  // Boþ, çünkü OnCreate DFM'den tetiklenmemiþ olabilir, SetupForClient'da yapýyoruz.
end;

procedure TForm12.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if Assigned(FChannelLine) then
  begin
    try
      Winapi.Winsock2.closesocket(FChannelLine.Handle);
    except
    end;
    FChannelLine := nil;
  end;

  if Assigned(FUnregister) and Assigned(FLine) then
    FUnregister(FLine);
  DetachCallbacks;
  Action := caFree;
end;

{ ---------------------------------------------------------------------------- }
{  Network                                                                       }
{ ---------------------------------------------------------------------------- }

procedure TForm12.RequestStartupList;
var
  JSON: TJSONObject;
  TargetLine: TncLine;
begin
  TargetLine := GetActiveLine;
  if not Assigned(FSendJSON) or not Assigned(TargetLine) then Exit;
  JSON := TJSONObject.Create;
  try
    JSON.AddPair('action', 'startup_list');
    FSendJSON(TargetLine, JSON);
  finally
    JSON.Free;
  end;
end;

procedure TForm12.HandleStartupJSON(JSONObj: TJSONObject);
var
  Arr     : TJSONArray;
  Obj     : TJSONObject;
  Item    : TListItem;
  i       : Integer;
  SName   : string;
  SType   : string;
  SPath   : string;
  SKey    : string;
begin
  if not Assigned(JSONObj) then Exit;

  Arr := JSONObj.Values['entries'] as TJSONArray;
  if not Assigned(Arr) then Exit;

  ListView1.Items.BeginUpdate;
  try
    ListView1.Items.Clear;
    for i := 0 to Arr.Count - 1 do
    begin
      Obj := Arr.Items[i] as TJSONObject;
      if not Assigned(Obj) then Continue;

      SName := '';
      SType := '';
      SPath := '';
      SKey  := '';

      if Assigned(Obj.Values['name'])     then SName := Obj.Values['name'].Value;
      if Assigned(Obj.Values['type'])     then SType := Obj.Values['type'].Value;
      if Assigned(Obj.Values['path'])     then SPath := Obj.Values['path'].Value;
      if Assigned(Obj.Values['reg_key'])  then SKey  := Obj.Values['reg_key'].Value;

      Item := ListView1.Items.Add;
      Item.Caption    := SName;
      Item.SubItems.Add(SType);
      Item.SubItems.Add(SPath);
      // reg_key'i gizli tutuyoruz ama silme iþleminde lazým olacak
      Item.SubItems.Add(SKey);
    end;
  finally
    ListView1.Items.EndUpdate;
  end;

  UpdateStatusBar;
end;

{ ---------------------------------------------------------------------------- }
{  UI Helpers                                                                    }
{ ---------------------------------------------------------------------------- }

procedure TForm12.UpdateStatusBar;
begin
  if StatusBar1.Panels.Count = 0 then
  begin
    with StatusBar1.Panels.Add do Width := 250;
  end;
  StatusBar1.Panels[0].Text :=
    'Toplam Startup Giriþi: ' + IntToStr(ListView1.Items.Count);
end;

procedure TForm12.ListView1MouseDown(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
var
  Item: TListItem;
begin
  if Button <> mbRight then Exit;
  Item := ListView1.GetItemAt(X, Y);
  if Assigned(Item) then
    Item.Selected := True;
end;

{ ---------------------------------------------------------------------------- }
{  Popup Menu Handlers                                                           }
{ ---------------------------------------------------------------------------- }

procedure TForm12.Refresh1Click(Sender: TObject);
begin
  RequestStartupList;
end;

procedure TForm12.Delete1Click(Sender: TObject);
var
  Item    : TListItem;
  JSON    : TJSONObject;
  SType   : string;
  SName   : string;
  SKey    : string;
  TargetLine: TncLine;
begin
  TargetLine := GetActiveLine;
  if not Assigned(FSendJSON) or not Assigned(TargetLine) then Exit;

  Item := ListView1.Selected;
  if not Assigned(Item) then
  begin
    MessageBox(Handle, 'Lütfen silmek istediðiniz giriþi seçin.', 'Startup Manager',
               MB_OK or MB_ICONWARNING);
    Exit;
  end;

  SName := Item.Caption;
  SType := Item.SubItems[0];
  SKey  := '';
  if Item.SubItems.Count > 2 then
    SKey := Item.SubItems[2];

  if MessageBox(Handle,
    PChar('Bu startup giriþi silinecek:' + #13#10 +
          'Ad: ' + SName + #13#10 +
          'Tür: ' + SType + #13#10#13#10 +
          'Devam etmek istiyor musunuz?'),
    'Startup Manager',
    MB_YESNO or MB_ICONQUESTION) <> IDYES then Exit;

  JSON := TJSONObject.Create;
  try
    JSON.AddPair('action',   'startup_delete');
    JSON.AddPair('name',     SName);
    JSON.AddPair('type',     SType);
    JSON.AddPair('reg_key',  SKey);
    FSendJSON(TargetLine, JSON);
  finally
    JSON.Free;
  end;

  // Listeden de kaldýr
  Item.Free;
  UpdateStatusBar;
end;

end.

