object Form10: TForm10
  Left = 0
  Top = 0
  Caption = 'Form10'
  ClientHeight = 441
  ClientWidth = 624
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  TextHeight = 15
  object PaintBox1: TPaintBox
    Left = 0
    Top = 41
    Width = 624
    Height = 381
    Align = alClient
    ExplicitLeft = 368
    ExplicitTop = 184
    ExplicitWidth = 105
    ExplicitHeight = 105
  end
  object Panel1: TPanel
    Left = 0
    Top = 0
    Width = 624
    Height = 41
    Align = alTop
    TabOrder = 0
    object Button1: TButton
      Left = 16
      Top = 9
      Width = 107
      Height = 25
      Caption = 'Start Capture'
      TabOrder = 0
      TabStop = False
      OnClick = Button1Click
    end
    object Button2: TButton
      Left = 399
      Top = 9
      Width = 89
      Height = 25
      Caption = 'Run Process'
      TabOrder = 1
      TabStop = False
    end
    object ComboBox1: TComboBox
      Left = 129
      Top = 12
      Width = 96
      Height = 23
      TabOrder = 2
      TabStop = False
      TextHint = 'Quality'
    end
    object ComboBox2: TComboBox
      Left = 256
      Top = 10
      Width = 137
      Height = 23
      TabOrder = 3
      TabStop = False
      TextHint = 'Select Process'
    end
    object Button3: TButton
      Left = 494
      Top = 9
      Width = 89
      Height = 25
      Caption = 'Custom'
      TabOrder = 4
      TabStop = False
    end
  end
  object StatusBar1: TStatusBar
    Left = 0
    Top = 422
    Width = 624
    Height = 19
    Panels = <>
  end
end
