object Form1: TForm1
  Left = 0
  Top = 0
  Caption = 'Night RAT <beta>'
  ClientHeight = 451
  ClientWidth = 810
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poDesigned
  TextHeight = 15
  object PageControl1: TPageControl
    Left = 0
    Top = 0
    Width = 810
    Height = 432
    ActivePage = Clients
    Align = alClient
    TabOrder = 0
    object Clients: TTabSheet
      Caption = 'Clients'
      object ListView1: TListView
        Left = 0
        Top = 0
        Width = 802
        Height = 402
        Align = alClient
        Columns = <
          item
            Caption = 'IP Adress'
            Width = 120
          end
          item
            Caption = 'Country'
            Width = 80
          end
          item
            Caption = 'ID'
            Width = 80
          end
          item
            Caption = 'Desktop Name'
            Width = 130
          end
          item
            Caption = 'Operating System'
            Width = 130
          end
          item
            Caption = 'Date'
            Width = 120
          end
          item
            Caption = 'UAC'
            Width = 75
          end
          item
            Caption = 'Anti Virus'
            Width = 140
          end>
        ReadOnly = True
        RowSelect = True
        PopupMenu = PopupMenu1
        TabOrder = 0
        ViewStyle = vsReport
      end
    end
    object Settings: TTabSheet
      Caption = 'Settings'
      ImageIndex = 1
      object GroupBox1: TGroupBox
        Left = 3
        Top = 3
        Width = 174
        Height = 126
        Caption = 'Port Settings'
        TabOrder = 0
        object Button1: TButton
          Left = 48
          Top = 80
          Width = 75
          Height = 25
          Caption = 'Listen'
          TabOrder = 0
          OnClick = Button1Click
        end
      end
      object SpinEdit1: TSpinEdit
        Left = 32
        Top = 40
        Width = 121
        Height = 24
        MaxValue = 65535
        MinValue = 0
        TabOrder = 1
        Value = 1337
      end
      object GroupBox2: TGroupBox
        Left = 3
        Top = 135
        Width = 174
        Height = 288
        Caption = 'Debug'
        TabOrder = 2
        object ToggleSwitch1: TToggleSwitch
          Left = 12
          Top = 32
          Width = 146
          Height = 20
          State = tssOn
          StateCaptions.CaptionOn = 'Connection Logs'
          StateCaptions.CaptionOff = 'Connection Logs'
          TabOrder = 0
        end
        object ToggleSwitch2: TToggleSwitch
          Left = 12
          Top = 58
          Width = 110
          Height = 20
          StateCaptions.CaptionOn = 'Extra Logs'
          StateCaptions.CaptionOff = 'Extra Logs'
          TabOrder = 1
        end
        object ToggleSwitch3: TToggleSwitch
          Left = 12
          Top = 84
          Width = 109
          Height = 20
          StateCaptions.CaptionOn = 'Error Logs'
          StateCaptions.CaptionOff = 'Error Logs'
          TabOrder = 2
        end
      end
    end
    object Logs: TTabSheet
      Caption = 'Logs'
      ImageIndex = 2
      object ListView2: TListView
        Left = 0
        Top = 0
        Width = 802
        Height = 402
        Align = alClient
        Color = clWhite
        Columns = <
          item
            Caption = 'Time'
            Width = 100
          end
          item
            Caption = 'Details'
            Width = 300
          end>
        PopupMenu = PopupMenu2
        TabOrder = 0
        ViewStyle = vsReport
      end
    end
    object TabSheet1: TTabSheet
      Caption = 'TabSheet1'
      ImageIndex = 3
    end
  end
  object StatusBar3: TStatusBar
    Left = 0
    Top = 432
    Width = 810
    Height = 19
    Panels = <
      item
        Text = 'Clients Online [0]'
        Width = 100
      end>
  end
  object ncTCPServer1: TncTCPServer
    Left = 732
    Top = 122
  end
  object PopupMenu1: TPopupMenu
    Left = 736
    Top = 178
    object SendMessage1: TMenuItem
      Caption = 'Send Message'
      OnClick = SendMessage1Click
    end
    object Information1: TMenuItem
      Caption = 'Information'
      OnClick = Information1Click
    end
    object ProcessManager1: TMenuItem
      Caption = 'Process Manager'
      OnClick = ProcessManager1Click
    end
    object RemoteShell1: TMenuItem
      Caption = 'Remote Shell'
      OnClick = RemoteShell1Click
    end
    object RemoteMonitoring1: TMenuItem
      Caption = 'Remote Monitoring'
      OnClick = RemoteMonitoring1Click
    end
    object Keylogger1: TMenuItem
      Caption = 'Keylogger'
      OnClick = Keylogger1Click
    end
    object OpenURL1: TMenuItem
      Caption = 'Open URL'
      OnClick = OpenURL1Click
    end
    object FileManager1: TMenuItem
      Caption = 'File Manager'
      OnClick = FileManager1Click
    end
    object HiddenVNC1: TMenuItem
      Caption = 'Hidden VNC'
      OnClick = HiddenVNC1Click
    end
  end
  object PopupMenu2: TPopupMenu
    Left = 740
    Top = 234
    object ClearLogs1: TMenuItem
      Caption = 'Clear Logs'
      OnClick = ClearLogs1Click
    end
  end
end
