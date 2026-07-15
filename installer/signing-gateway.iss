; ============================================================================
;  Signing Gateway - Bo cai dat Windows
;  Bien dich:  iscc installer\signing-gateway.iss
;  Ket qua:    dist\SignerGateway.exe
;
;  LUU Y: trong section [Code], KHONG dung comment kieu { ... }
;  vi noi dung co chua dau ngoac nhon (JSON) se lam Pascal hieu nham.
;  Chi dung comment kieu //
; ============================================================================

#define AppName      "Signing Gateway"
#define AppVersion   "0.2.0"
#define AppPublisher "VNPT HIS4"
#define ExeName      "signing-gateway.exe"

[Setup]
AppId={{8F3C1A72-4E5D-4B9A-9C21-7D6E0F1B2A34}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\SigningGateway
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=SignerGateway
; Icon cho file cai dat va cua so wizard. Dat vnpt.ico vao thu muc installer\
SetupIconFile=vnpt.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
UninstallDisplayIcon={app}\{#ExeName}

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\dist\{#ExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md";       DestDir: "{app}"; Flags: ignoreversion isreadme
; cloudflared.exe la TUY CHON
Source: "cloudflared.exe";    DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
; license.txt: dontcopy = wizard doc luc cai, KHONG cai vao {app}
Source: "license.txt";        Flags: dontcopy noencryption skipifsourcedoesntexist
; Icon VNPT: cai vao {app} de shortcut dung lam bieu tuong
Source: "vnpt.ico";           DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
; File cai VNPT-CA Plugin. TU DAT vao thu muc installer\ neu ban CO QUYEN
; phan phoi lai plugin cua VNPT. Neu khong co file nay, bo cai bo qua buoc
; cai plugin (nguoi dung tu cai). skipifsourcedoesntexist = khong co thi bo qua.
Source: "vnpt-ca-plugin-setup.exe"; Flags: dontcopy noencryption skipifsourcedoesntexist

[Dirs]
; Config + audit log KHONG nam trong Program Files: thu muc do khong ghi duoc
; neu thieu quyen, va Windows se ao hoa file ghi sang noi khac -> log bien mat.
Name: "{commonappdata}\SigningGateway"; Permissions: users-modify

[Icons]
Name: "{group}\Signer Gateway";     Filename: "{app}\{#ExeName}"; WorkingDir: "{commonappdata}\SigningGateway"; IconFilename: "{app}\vnpt.ico"
Name: "{group}\Trang trang thai";   Filename: "http://127.0.0.1:8080/"
Name: "{group}\Chan doan plugin";   Filename: "{cmd}"; Parameters: "/k ""{app}\{#ExeName}"" --probe"; WorkingDir: "{app}"
Name: "{group}\Thu muc audit log";  Filename: "{commonappdata}\SigningGateway"
Name: "{group}\Go cai dat";         Filename: "{uninstallexe}"

[Run]
; Cai VNPT-CA Plugin truoc (neu co kem file). /VERYSILENT = cai ngam.
; Chi chay neu file ton tai (Check: FileExists).
Filename: "{tmp}\vnpt-ca-plugin-setup.exe"; Parameters: "/VERYSILENT /NORESTART"; \
  StatusMsg: "Dang cai VNPT-CA Plugin..."; Check: PluginSetupExists; Flags: waituntilterminated

; Gateway tu spawn cloudflared lam tien trinh con -> khong cai service rieng.
Filename: "{app}\{#ExeName}"; \
  WorkingDir: "{commonappdata}\SigningGateway"; \
  Description: "Khoi dong Signing Gateway ngay bay gio"; \
  Flags: postinstall nowait skipifsilent

[UninstallDelete]
Type: files; Name: "{commonstartup}\Signer Gateway.lnk"
Type: files; Name: "{app}\run-hidden.vbs"

; ============================================================================
[Code]

var
  CfgPage: TInputQueryWizardPage;
  LicPage: TInputQueryWizardPage;
  TunPage: TInputOptionWizardPage;
  TokPage: TInputQueryWizardPage;
  TgPage: TInputQueryWizardPage;
  OptPage: TInputOptionWizardPage;
  BundledLicense: String;
  HasPluginSetup: Boolean;

// "https://his4-dev.vnpthis.vn/" -> "his4-dev.vnpthis.vn"
// SDK cua VNPT gui window.location.hostname, KHONG kem scheme.
// Gui ca scheme -> plugin tra license khong khop -> tu choi ky.
function HostnameOf(Url: String): String;
var
  P: Integer;
begin
  Result := Trim(Url);
  P := Pos('://', Result);
  if P > 0 then Result := Copy(Result, P + 3, Length(Result));
  P := Pos('/', Result);
  if P > 0 then Result := Copy(Result, 1, P - 1);
  P := Pos(':', Result);
  if P > 0 then Result := Copy(Result, 1, P - 1);
  Result := Lowercase(Result);
end;

// Doc license nhung san trong bo cai (installer\license.txt).
// Bo qua dong trong va dong bat dau bang #.
// Bo cai co kem file cai VNPT-CA Plugin khong?
// Kiem tra bang cach thu giai nen no ra {tmp}. Neu bo cai khong nhung file
// (skipifsourcedoesntexist) thi ExtractTemporaryFile se nem exception.
function DetectPluginSetup(): Boolean;
begin
  Result := False;
  try
    ExtractTemporaryFile('vnpt-ca-plugin-setup.exe');
    Result := True;
  except
    Result := False;
  end;
end;

function PluginSetupExists(): Boolean;
begin
  Result := HasPluginSetup;
end;

function ReadBundledLicense(): String;
var
  Lines: TArrayOfString;
  I: Integer;
  L: String;
begin
  Result := '';

  // ExtractTemporaryFile nem exception neu license.txt khong duoc nhung vao
  // bo cai (do co skipifsourcedoesntexist). Phai boc try/except.
  try
    ExtractTemporaryFile('license.txt');
  except
    Exit;
  end;

  if not LoadStringsFromFile(ExpandConstant('{tmp}\license.txt'), Lines) then Exit;

  for I := 0 to GetArrayLength(Lines) - 1 do
  begin
    L := Trim(Lines[I]);
    if (L <> '') and (Copy(L, 1, 1) <> '#') then
    begin
      Result := L;
      Exit;
    end;
  end;
end;

function CheckVnptPlugin(): Boolean;
begin
  Result :=
    DirExists(ExpandConstant('{commonpf}\VNPT-CA Plugin')) or
    DirExists(ExpandConstant('{commonpf32}\VNPT-CA Plugin')) or
    DirExists(ExpandConstant('{localappdata}\VNPT-CA Plugin'));
end;

procedure InitializeWizard();
var
  Msg: String;
begin
  BundledLicense := ReadBundledLicense();
  HasPluginSetup := DetectPluginSetup();

  // Chi canh bao khi plugin CHUA cai VA bo cai KHONG kem file cai plugin.
  // Neu bo cai co kem plugin thi no se duoc cai o buoc [Run] -> khong canh bao.
  if (not CheckVnptPlugin()) and (not HasPluginSetup) then
  begin
    Msg :=
      'Khong tim thay VNPT-CA Plugin tren may nay.' + #13#10#13#10 +
      'Signing Gateway BAT BUOC can VNPT-CA Plugin de giao tiep voi USB Token.' + #13#10#13#10 +
      'Ban van co the tiep tuc cai dat, nhung phai cai VNPT-CA Plugin' + #13#10 +
      'truoc khi he thong ky duoc.' + #13#10#13#10 +
      'Tai tai: https://vnpt-ca.vn';
    CreateOutputMsgPage(wpWelcome,
      'Thieu thanh phan bat buoc',
      'VNPT-CA Plugin chua duoc cai dat',
      Msg);
  end;

  CfgPage := CreateInputQueryPage(wpSelectDir,
    'Cau hinh Signing Gateway',
    'Nhap thong tin ket noi voi he thong HIS4',
    'Cac thong tin nay do doi ngu HIS4 cung cap.');
  CfgPage.Add('Ma benh vien (tenantId), vi du: bv-bach-mai:', False);
  CfgPage.Add('Secret dung chung voi backend HIS4 (64 ky tu hex):', False);
  CfgPage.Add('Origin cua HIS4:', False);
  CfgPage.Values[2] := 'https://his4-dev.vnpthis.vn';

  // License VNPT-CA Plugin. Khong co license, plugin tu choi moi lenh ky
  // voi loi: code -1, error "License not set for: <domain>"
  LicPage := CreateInputQueryPage(CfgPage.ID,
    'License VNPT-CA Plugin',
    'Khong co license, plugin se TU CHOI moi lenh ky',
    'Chuoi license do VNPT cap, gan voi domain. Rat dai (hon 3000 ky tu) - ' +
    'dan nguyen, khong xuong dong.');
  LicPage.Add('License key:', False);
  LicPage.Values[0] := BundledLicense;

  // Quick tunnel KHONG can token. Phai hoi ro, khong suy dien tu o token.
  TunPage := CreateInputOptionPage(LicPage.ID,
    'Cloudflare Tunnel',
    'Dua gateway ra ngoai de HIS4 goi duoc',
    'Chon mot trong ba:',
    True, False);
  TunPage.Add('Tunnel co dinh - CAN token (dung khi trien khai that)');
  TunPage.Add('Quick tunnel - KHONG can token, URL ngau nhien (chi de test)');
  TunPage.Add('Tat tunnel - tu cau hinh sau');
  TunPage.SelectedValueIndex := 1;

  TokPage := CreateInputQueryPage(TunPage.ID,
    'Cloudflare Tunnel token',
    'Dan token vao day',
    'Lay tai: Cloudflare Zero Trust > Networks > Tunnels > Create a tunnel. ' +
    'Token la chuoi dai bat dau bang eyJ...');
  TokPage.Add('Token:', False);

  // Trang Telegram: gui log/canh bao len Telegram (tuy chon)
  TgPage := CreateInputQueryPage(TokPage.ID,
    'Telegram (tuy chon)',
    'Nhan canh bao va loi qua Telegram',
    'De trong neu khong dung. Tao bot: nhan @BotFather -> /newbot. ' +
    'Lay chatId: nhan tin cho bot roi mo api.telegram.org/bot<token>/getUpdates');
  TgPage.Add('Bot Token:', False);
  TgPage.Add('Chat ID:', False);

  // Trang tuy chon hien thi
  OptPage := CreateInputOptionPage(TgPage.ID,
    'Tuy chon hien thi',
    'Cua so dong lenh (CMD)',
    'Khi gateway chay:',
    False, False);
  OptPage.Add('Hien cua so CMD (xem log truc tiep)');
  OptPage.Add('An cua so CMD (chay ngam - dung khi da co Telegram)');
  OptPage.Values[0] := True;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  // License da nhung san khi build -> khong hoi nua
  if PageID = LicPage.ID then
    Result := (BundledLicense <> '');
  // Chi hoi token khi chon tunnel co dinh
  if PageID = TokPage.ID then
    Result := (TunPage.SelectedValueIndex <> 0);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  S: String;
begin
  Result := True;

  if CurPageID = CfgPage.ID then
  begin
    S := Trim(CfgPage.Values[1]);
    if (S <> '') and (Length(S) <> 64) then
    begin
      MsgBox('Secret phai dai dung 64 ky tu hex.' + #13#10#13#10 +
             'Sinh bang lenh:' + #13#10 +
             'node -e "console.log(require(''crypto'').randomBytes(32).toString(''hex''))"',
             mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if Trim(CfgPage.Values[2]) = '' then
    begin
      MsgBox('Phai nhap Origin cua HIS4.', mbError, MB_OK);
      Result := False;
    end;
  end;

  if CurPageID = LicPage.ID then
  begin
    if Trim(LicPage.Values[0]) = '' then
    begin
      if MsgBox('CHUA NHAP LICENSE.' + #13#10#13#10 +
                'Khong co license, VNPT-CA Plugin se TU CHOI moi lenh ky.' + #13#10 +
                'Plugin tra ve: code -1, error "License not set for: ..."' + #13#10#13#10 +
                'Van tiep tuc? (co the them sau vao config.json)',
                mbConfirmation, MB_YESNO) = IDNO then
        Result := False;
    end;
  end;

  if CurPageID = TokPage.ID then
  begin
    if Trim(TokPage.Values[0]) = '' then
    begin
      MsgBox('Da chon tunnel co dinh nen phai co token.' + #13#10#13#10 +
             'Khong co token thi quay lai chon "Quick tunnel".', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

procedure WriteConfig();
var
  DataDir, CfgFile, TunnelOn, TunnelTok, Lic, TgOn: String;
  Lines: TArrayOfString;
begin
  DataDir := ExpandConstant('{commonappdata}\SigningGateway');
  CfgFile := DataDir + '\config.json';

  // Config da ton tai (cai lai / nang cap).
  // KHONG am tham bo qua: nguoi dung vua go het thong tin trong wizard,
  // bo qua im lang lam ho tuong da luu ma thuc te khong.
  if FileExists(CfgFile) then
  begin
    if MsgBox('Da co config.json tu lan cai truoc:' + #13#10 +
              CfgFile + #13#10#13#10 +
              'GHI DE bang thong tin vua nhap trong bo cai?' + #13#10#13#10 +
              'Chon YES  = dung thong tin moi (config cu bi mat)' + #13#10 +
              'Chon NO   = giu nguyen config cu (bo qua thong tin vua nhap)',
              mbConfirmation, MB_YESNO) = IDNO then
      Exit;

    // Sao luu config cu truoc khi ghi de
    CopyFile(CfgFile, CfgFile + '.bak', False);
  end;

  // 0 = tunnel co dinh (co token), 1 = quick tunnel, 2 = tat
  if TunPage.SelectedValueIndex = 2 then
    TunnelOn := 'false'
  else
    TunnelOn := 'true';

  if TunPage.SelectedValueIndex = 0 then
    TunnelTok := Trim(TokPage.Values[0])
  else
    TunnelTok := '';

  if BundledLicense <> '' then
    Lic := BundledLicense
  else
    Lic := Trim(LicPage.Values[0]);

  // Telegram bat khi co ca bot token va chat id
  if (Trim(TgPage.Values[0]) <> '') and (Trim(TgPage.Values[1]) <> '') then
    TgOn := 'true'
  else
    TgOn := 'false';

  SetArrayLength(Lines, 31);
  Lines[0]  := '{';
  Lines[1]  := '  "host": "127.0.0.1",';
  Lines[2]  := '  "port": 8080,';
  Lines[3]  := '  "allowedOrigins": ["' + Trim(CfgPage.Values[2]) + '"],';
  Lines[4]  := '  "hisSharedSecret": "' + Trim(CfgPage.Values[1]) + '",';
  Lines[5]  := '  "tenantId": "' + Trim(CfgPage.Values[0]) + '",';
  Lines[6]  := '  "licenseKey": "' + Lic + '",';
  Lines[7]  := '  "pluginDomain": "' + HostnameOf(CfgPage.Values[2]) + '",';
  Lines[8]  := '  "pluginPorts": [4433, 4434, 4435, 9201, 9202],';
  Lines[9]  := '  "certificateSerial": "",';
  Lines[10] := '  "tsaUrl": "",';
  Lines[11] := '  "tsaUsername": "",';
  Lines[12] := '  "tsaPassword": "",';
  Lines[13] := '  "signTimeoutMs": 120000,';
  Lines[14] := '  "jobTtlMinutes": 30,';
  Lines[15] := '  "maxPdfBytes": 20971520,';
  Lines[16] := '  "tunnel": {';
  Lines[17] := '    "enabled": ' + TunnelOn + ',';
  Lines[18] := '    "token": "' + TunnelTok + '",';
  Lines[19] := '    "exePath": ""';
  Lines[20] := '  },';
  Lines[21] := '  "telegram": {';
  Lines[22] := '    "enabled": ' + TgOn + ',';
  Lines[23] := '    "botToken": "' + Trim(TgPage.Values[0]) + '",';
  Lines[24] := '    "chatId": "' + Trim(TgPage.Values[1]) + '",';
  Lines[25] := '    "minLevel": "warn",';
  Lines[26] := '    "silent": false';
  Lines[27] := '  }';
  Lines[28] := '}';
  Lines[29] := '';

  // SaveStringsToUTF8File ghi kem BOM (EF BB BF) -> JSON.parse crash.
  // Noi dung config toan ASCII nen SaveStringsToFile (khong BOM) la du.
  if not SaveStringsToFile(CfgFile, Lines, False) then
    MsgBox('Khong ghi duoc config.json vao:' + #13#10 + CfgFile, mbError, MB_OK);
end;

// Chay khi DANG NHAP, KHONG phai Windows Service.
// Ly do: VNPT Plugin bat hop thoai nhap PIN. Service chay o session 0 khong co
// desktop -> hop thoai hien o noi khong ai bam duoc -> moi request ky treo.
procedure CreateStartupShortcut();
var
  Vbs: TArrayOfString;
  VbsPath: String;
begin
  if OptPage.Values[1] then
  begin
    // AN CMD: exe la console app, SW_HIDE khong an triet de duoc.
    // Tao 1 file VBS chay exe hoan toan an (WindowStyle = 0).
    VbsPath := ExpandConstant('{app}\run-hidden.vbs');
    SetArrayLength(Vbs, 3);
    Vbs[0] := 'Set s = CreateObject("WScript.Shell")';
    Vbs[1] := 's.CurrentDirectory = "' + ExpandConstant('{commonappdata}\SigningGateway') + '"';
    Vbs[2] := 's.Run """' + ExpandConstant('{app}\signing-gateway.exe') + '""", 0, False';
    SaveStringsToFile(VbsPath, Vbs, False);

    CreateShellLink(
      ExpandConstant('{commonstartup}\Signer Gateway.lnk'),
      'Signer Gateway (an)',
      'wscript.exe',
      '"' + VbsPath + '"',
      ExpandConstant('{commonappdata}\SigningGateway'),
      '', 0, SW_HIDE);
  end
  else
  begin
    // HIEN CMD: chay truc tiep, cua so thu nho
    CreateShellLink(
      ExpandConstant('{commonstartup}\Signer Gateway.lnk'),
      'Signer Gateway',
      ExpandConstant('{app}\signing-gateway.exe'),
      '',
      ExpandConstant('{commonappdata}\SigningGateway'),
      '', 0, SW_SHOWMINNOACTIVE);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    WriteConfig();
    CreateStartupShortcut();
  end;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfo, MemoDirInfo, MemoTypeInfo,
  MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
var
  S: String;
begin
  S := MemoDirInfo + NewLine + NewLine;
  S := S + 'Cau hinh:' + NewLine;
  S := S + Space + 'Ma benh vien: ' + Trim(CfgPage.Values[0]) + NewLine;
  S := S + Space + 'Origin HIS4:  ' + Trim(CfgPage.Values[2]) + NewLine;
  S := S + Space + 'Domain plugin: ' + HostnameOf(CfgPage.Values[2]) + NewLine;

  if Trim(CfgPage.Values[1]) <> '' then
    S := S + Space + 'Secret HIS4:  da nhap' + NewLine
  else
    S := S + Space + 'Secret HIS4:  CHUA NHAP - khong ky duoc cho toi khi them' + NewLine;

  if BundledLicense <> '' then
    S := S + Space + 'License plugin: nhung san trong bo cai' + NewLine
  else if Trim(LicPage.Values[0]) <> '' then
    S := S + Space + 'License plugin: da nhap thu cong' + NewLine
  else
    S := S + Space + 'License plugin: CHUA CO - PLUGIN SE TU CHOI MOI LENH KY' + NewLine;

  case TunPage.SelectedValueIndex of
    0: S := S + Space + 'Cloudflare Tunnel: co dinh (co token)' + NewLine;
    1: S := S + Space + 'Cloudflare Tunnel: quick - URL doi moi lan chay' + NewLine;
    2: S := S + Space + 'Cloudflare Tunnel: tat' + NewLine;
  end;

  if (Trim(TgPage.Values[0]) <> '') and (Trim(TgPage.Values[1]) <> '') then
    S := S + Space + 'Telegram: BAT (gui canh bao + loi)' + NewLine
  else
    S := S + Space + 'Telegram: tat' + NewLine;

  if OptPage.Values[1] then
    S := S + Space + 'Cua so CMD: AN (chay ngam)' + NewLine
  else
    S := S + Space + 'Cua so CMD: hien' + NewLine;

  if HasPluginSetup then
    S := S + Space + 'VNPT-CA Plugin: se duoc CAI TU DONG' + NewLine
  else if CheckVnptPlugin() then
    S := S + Space + 'VNPT-CA Plugin: da co san tren may' + NewLine
  else
    S := S + Space + 'VNPT-CA Plugin: CHUA CO - phai tu cai truoc khi ky duoc' + NewLine;

  S := S + NewLine + 'Sau khi cai:' + NewLine;
  S := S + Space + 'Gateway tu chay moi khi dang nhap Windows.' + NewLine;
  S := S + Space + 'Lan ky dau tien sau moi lan khoi dong may se hien hop thoai PIN.' + NewLine;
  S := S + Space + 'Phai co nguoi nhap PIN ngay tren may chu nay.' + NewLine;
  Result := S;
end;
