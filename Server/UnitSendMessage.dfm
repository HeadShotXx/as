object Form2: TForm2
  Left = 0
  Top = 0
  BorderStyle = bsSingle
  Caption = 'Send Message'
  ClientHeight = 262
  ClientWidth = 276
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  TextHeight = 15
  object Label1: TLabel
    Left = 8
    Top = 205
    Width = 56
    Height = 15
    Caption = 'lblTargetID'
  end
  object Button1: TButton
    Left = 0
    Top = 221
    Width = 276
    Height = 41
    Align = alBottom
    Caption = 'Send Message'
    TabOrder = 0
    OnClick = Button1Click
  end
  object Edit1: TEdit
    Left = 8
    Top = 3
    Width = 260
    Height = 23
    TabOrder = 1
    Text = 'Title'
    TextHint = 'asd'
  end
  object ComboBox1: TComboBox
    Left = 8
    Top = 176
    Width = 260
    Height = 23
    TabOrder = 2
    TextHint = 'Select box'
    Items.Strings = (
      'info'
      'error'
      'warning')
  end
  object Memo1: TMemo
    Left = 8
    Top = 32
    Width = 260
    Height = 138
    TabOrder = 3
  end
end
