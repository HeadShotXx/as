object Form4: TForm4
  Left = 0
  Top = 0
  Caption = 'Process Manager'
  ClientHeight = 507
  ClientWidth = 614
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
    Width = 614
    Height = 488
    Align = alClient
    Columns = <
      item
        AutoSize = True
        Caption = 'Name'
        MinWidth = 100
      end
      item
        AutoSize = True
        Caption = 'PID'
        MinWidth = 60
      end>
    PopupMenu = PopupMenu1
    TabOrder = 0
    ViewStyle = vsReport
  end
  object StatusBar1: TStatusBar
    Left = 0
    Top = 488
    Width = 614
    Height = 19
    Panels = <
      item
        Text = 'Process [0]'
        Width = 100
      end>
  end
  object PopupMenu1: TPopupMenu
    Left = 528
    Top = 56
    object KillProcess1: TMenuItem
      Caption = 'Kill Process'
      OnClick = KillProcess1Click
    end
    object RestartProcess1: TMenuItem
      Caption = 'Restart Process'
      OnClick = RestartProcess1Click
    end
    object RefreshTasks1: TMenuItem
      Caption = 'Refresh Tasks'
      OnClick = RefreshTasks1Click
    end
  end
end
