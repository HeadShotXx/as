object Form6: TForm6
  Left = 0
  Top = 0
  Caption = 'Form6'
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
    ExplicitLeft = 232
    ExplicitTop = 120
    ExplicitWidth = 105
    ExplicitHeight = 105
  end
  object StatusBar1: TStatusBar
    Left = 0
    Top = 422
    Width = 624
    Height = 19
    Panels = <
      item
        Text = 'Capturing [Off]'
        Width = 90
      end
      item
        Text = 'Size []'
        Width = 80
      end>
  end
  object Panel1: TPanel
    Left = 0
    Top = 0
    Width = 624
    Height = 41
    Align = alTop
    TabOrder = 1
    ExplicitTop = -2
    object Button1: TButton
      Left = 17
      Top = 7
      Width = 105
      Height = 25
      Caption = 'Start Capture'
      TabOrder = 0
    end
    object CheckBox1: TCheckBox
      Left = 431
      Top = 11
      Width = 82
      Height = 17
      Caption = 'Keyboard'
      TabOrder = 1
    end
    object CheckBox2: TCheckBox
      Left = 519
      Top = 11
      Width = 83
      Height = 17
      Caption = 'Mouse'
      TabOrder = 2
    end
    object ComboBox2: TComboBox
      Left = 128
      Top = 8
      Width = 170
      Height = 23
      TabOrder = 3
      Text = 'Devices'
    end
  end
  object ComboBox1: TComboBox
    Left = 304
    Top = 8
    Width = 121
    Height = 23
    TabOrder = 2
    Text = 'Quality'
    Items.Strings = (
      '%10'
      '%20'
      '%30'
      '%40'
      '%50'
      '%60'
      '%70'
      '%80'
      '%90'
      '%100')
  end
end
