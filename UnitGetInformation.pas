unit UnitGetInformation;

interface

uses
  Winapi.Windows, Winapi.Messages,
  System.SysUtils, System.Variants, System.Classes, System.JSON,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.ComCtrls,
  ncLines;

type
  TForm3 = class(TForm)
    ListView1: TListView;
    StatusBar1: TStatusBar;
  private
    FClientLine : TncLine;
    procedure InitListView;
    procedure SetInfoValue(const AKey, AValue: string);
  public
    procedure SetupForClient(aLine: TncLine; const ClientID: string);
    procedure HandleInfoJSON(JSONObj: TJSONObject);
  end;

var
  Form3: TForm3;

implementation

{$R *.dfm}

const
  INFO_KEYS: array[0..21] of string = (
    'UserName', 'PCName', 'OS', 'Client', 'Process', 'DateTime',
    'ListDrivers', 'HDDSerial', 'ListUSB', 'GPU', 'CPU', 'Ram',
    'SystemProductName', 'MachineType', 'LastReboot', 'Antivirus',
    'Firewall', 'MacAddress', 'DefaultBrowser', 'CurrentLang',
    'Platform', 'Battery'
  );

procedure TForm3.InitListView;
var
  Key   : string;
  Item  : TListItem;
  Col   : TListColumn;
begin
  ListView1.Items.BeginUpdate;
  try
    ListView1.ViewStyle := vsReport;
    ListView1.GridLines := True;
    ListView1.Columns.Clear;

    // Create columns (Ensuring they exist if not defined in DFM)
    Col := ListView1.Columns.Add;
    Col.Caption := 'Property';
    Col.Width := 150;

    Col := ListView1.Columns.Add;
    Col.Caption := 'Value';
    Col.Width := 300;

    ListView1.Items.Clear;
    for Key in INFO_KEYS do
    begin
      Item         := ListView1.Items.Add;
      Item.Caption := Key;
      Item.SubItems.Add('Waiting...');
    end;
  finally
    ListView1.Items.EndUpdate;
  end;

  StatusBar1.Panels[0].Text := 'Informations [0]';
end;

// Updates the value in the status bar based on received information.
procedure TForm3.SetInfoValue(const AKey, AValue: string);
var
  i     : Integer;
  Count : Integer;
begin
  Count := 0;

  ListView1.Items.BeginUpdate;
  try
    for i := 0 to ListView1.Items.Count - 1 do
    begin
      if SameText(ListView1.Items[i].Caption, AKey) then
      begin
        if AValue = '' then
          ListView1.Items[i].SubItems[0] := 'N/A'
        else
          ListView1.Items[i].SubItems[0] := AValue;
      end;

      if (ListView1.Items[i].SubItems.Count > 0) and (ListView1.Items[i].SubItems[0] <> 'Waiting...') then
        Inc(Count);
    end;
  finally
    ListView1.Items.EndUpdate;
  end;

  StatusBar1.Panels[0].Text := 'Informations [' + IntToStr(Count) + ']';
end;

procedure TForm3.SetupForClient(aLine: TncLine; const ClientID: string);
begin
  FClientLine := aLine;
  Caption     := 'Information - ' + ClientID;
  InitListView;
end;

// Handles information received from the client.
procedure TForm3.HandleInfoJSON(JSONObj: TJSONObject);
var
  Key   : string;
  JVal  : TJSONValue;
  LKey  : string;
begin
  if not Assigned(JSONObj) then Exit;

  ListView1.Items.BeginUpdate;
  try
    for Key in INFO_KEYS do
    begin
      LKey := LowerCase(Key);
      // TJSONObject.Values usage is case-sensitive.
      JVal := JSONObj.Values[LKey];

      if Assigned(JVal) then
        SetInfoValue(Key, JVal.Value)
      else
        SetInfoValue(Key, 'N/A');
    end;
  finally
    ListView1.Items.EndUpdate;
  end;
end;

end.

