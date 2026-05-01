unit UnitSendMessage;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls;

type
  TForm2 = class(TForm)
    Button1: TButton;      // Designer'da ModalResult özelliðini mrOk yapýn
    Edit1: TEdit;        // Text
    ComboBox1: TComboBox;  // Type
    Label1: TLabel;
    Memo1: TMemo;
    procedure Button1Click(Sender: TObject);
  public
    { Public declarations }
  end;

var
  Form2: TForm2;

implementation

{$R *.dfm}

procedure TForm2.Button1Click(Sender: TObject);
begin
  if Memo1.Text = '' then
  begin
    ShowMessage('Mesaj metni boþ olamaz!');
    Exit;
  end;
  ModalResult := mrOk; // Bu satýr formu kapatýr ve Form1'e onay verir
end;

end.
