object Form9: TForm9
  Left = 0
  Top = 0
  Caption = 'Form9'
  ClientHeight = 447
  ClientWidth = 682
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  TextHeight = 15
  object ListView1: TListView
    Left = 0
    Top = 41
    Width = 682
    Height = 387
    Align = alClient
    Columns = <
      item
        AutoSize = True
        Caption = 'Name'
        MaxWidth = 200
        MinWidth = 60
      end
      item
        AutoSize = True
        Caption = 'Date Modified'
        MaxWidth = 120
        MinWidth = 100
      end
      item
        AutoSize = True
        Caption = 'Type'
        MaxWidth = 150
        MinWidth = 120
      end
      item
        AutoSize = True
        Caption = 'Size'
        MaxWidth = 120
        MinWidth = 100
      end>
    PopupMenu = PopupMenu1
    TabOrder = 0
    ViewStyle = vsReport
  end
  object Panel1: TPanel
    Left = 0
    Top = 0
    Width = 682
    Height = 41
    Align = alTop
    TabOrder = 1
    object Edit1: TEdit
      Left = 178
      Top = 10
      Width = 487
      Height = 23
      TabOrder = 0
      TextHint = 'File Path'
    end
    object Geri: TButton
      Left = 16
      Top = 9
      Width = 75
      Height = 25
      Caption = 'Geri'
      TabOrder = 1
    end
    object Yenile: TButton
      Left = 97
      Top = 9
      Width = 75
      Height = 25
      Caption = 'Yenile'
      TabOrder = 2
    end
  end
  object StatusBar1: TStatusBar
    Left = 0
    Top = 428
    Width = 682
    Height = 19
    Panels = <>
    SimplePanel = True
  end
  object PopupMenu1: TPopupMenu
    Left = 616
    Top = 96
    object Delete1: TMenuItem
      Caption = 'Delete'
      OnClick = Delete1Click
    end
    object Rename1: TMenuItem
      Caption = 'Rename'
      OnClick = Rename1Click
    end
    object Delete2: TMenuItem
      Caption = 'Execute'
      object Normal1: TMenuItem
        Caption = 'Normal'
        OnClick = Normal1Click
      end
      object Normal2: TMenuItem
        Caption = 'Hidden'
        OnClick = Normal2Click
      end
      object RunAs1: TMenuItem
        Caption = 'RunAs'
        OnClick = RunAs1Click
      end
    end
    object NewFolder1: TMenuItem
      Caption = 'New Folder'
      OnClick = NewFolder1Click
    end
    object Download1: TMenuItem
      Caption = 'Download'
      OnClick = Download1Click
    end
    object Upload1: TMenuItem
      Caption = 'Upload'
      OnClick = Upload1Click
    end
    object Copy1: TMenuItem
      Caption = 'Copy'
      OnClick = Copy1Click
    end
    object Paste1: TMenuItem
      Caption = 'Paste'
      OnClick = Paste1Click
    end
  end
end
