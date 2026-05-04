unit UnitFileManager;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls, Vcl.ExtCtrls,
  Vcl.Menus;

type
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
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form9: TForm9;

implementation

{$R *.dfm}

procedure TForm9.Copy1Click(Sender: TObject);
begin
//Popup Copy
end;

procedure TForm9.Delete1Click(Sender: TObject);
begin
//Popup Delete
end;

procedure TForm9.Download1Click(Sender: TObject);
begin
//Popup Download
end;

procedure TForm9.NewFolder1Click(Sender: TObject);
begin
//Popup New Folder
end;

procedure TForm9.Normal1Click(Sender: TObject);
begin
//Popup Execute > Normal
end;

procedure TForm9.Normal2Click(Sender: TObject);
begin
//Popup Execute > Hidden
end;

procedure TForm9.Paste1Click(Sender: TObject);
begin
//Popup Paste
end;

procedure TForm9.Rename1Click(Sender: TObject);
begin
//Popup Rename
end;

procedure TForm9.RunAs1Click(Sender: TObject);
begin
//popup Execute > RunAs
end;

procedure TForm9.Upload1Click(Sender: TObject);
begin
//Popup Upload
end;

end.
