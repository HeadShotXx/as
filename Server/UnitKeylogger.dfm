object Form7: TForm7
  Left = 0
  Top = 0
  Caption = 'Form7'
  ClientHeight = 441
  ClientWidth = 624
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  TextHeight = 15
  object StatusBar1: TStatusBar
    Left = 0
    Top = 422
    Width = 624
    Height = 19
    Panels = <
      item
        Text = 'Status []'
        Width = 50
      end>
    ExplicitLeft = 88
    ExplicitTop = 352
    ExplicitWidth = 0
  end
  object Panel1: TPanel
    Left = 0
    Top = 0
    Width = 624
    Height = 41
    Align = alTop
    TabOrder = 1
    object Button1: TButton
      Left = 16
      Top = 9
      Width = 97
      Height = 25
      Caption = 'Start Capture'
      TabOrder = 0
      OnClick = Button1Click
    end
    object Button2: TButton
      Left = 119
      Top = 10
      Width = 90
      Height = 25
      Caption = 'Save All'
      TabOrder = 1
      OnClick = Button2Click
    end
  end
  object Memo1: TMemo
    Left = 0
    Top = 41
    Width = 624
    Height = 381
    Align = alClient
    TabOrder = 2
    ExplicitLeft = 160
    ExplicitTop = 200
    ExplicitWidth = 185
    ExplicitHeight = 89
  end
end
