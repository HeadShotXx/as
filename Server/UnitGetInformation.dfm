object Form3: TForm3
  Left = 0
  Top = 0
  Caption = 'Information'
  ClientHeight = 497
  ClientWidth = 449
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  TextHeight = 15
  object ListView1: TListView
    Left = 0
    Top = 0
    Width = 449
    Height = 478
    Align = alClient
    Columns = <
      item
        AutoSize = True
        Caption = 'Information'
      end>
    TabOrder = 0
    ViewStyle = vsReport
  end
  object StatusBar1: TStatusBar
    Left = 0
    Top = 478
    Width = 449
    Height = 19
    Panels = <
      item
        Text = 'Informations [0]'
        Width = 120
      end>
  end
end
