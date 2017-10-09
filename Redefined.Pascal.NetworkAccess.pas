unit Redefined.Pascal.NetworkAccess;

{ ***************************************************************************

  Copyright (c) 2015-2017 Enrique Fuentes

  Unit         : Redefined NetworkAccess
  Description  : Windows Networking Info and Scrapping methods
  Author       : Turric4n
  Version      : 1.0
  Created      : 11/07/2017
  Modified     : 09/10/2017
  ARCH         : x86 & x86/64
  SO           : NT4.0 or better
  Unit Dependencies : Quick.Network


 ***************************************************************************

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

 *************************************************************************** }

interface

uses
  SysUtils, Classes, Windows, Registry, Quick.Network, IPtypes, Winapi.Winsock2;

{
  IsWrongIP : testing if IP address is valid
  IPAddrToName: Get Machines name from IP address
  MACAddress : MAC address;
  IPAddress : IP address;
  DefaultUser : User name;
  ComputerName: Computer name;
  DNSServers : available DNS servers;
  NWComputers : available Machines on network NETBIOS;
  GetNWCompARP : available machines on newtwork by Ip/Name resolution;
  DomainName : domain name;
  InternetConnected: Internet connection type(None, Proxy, Dialup);
}

const
  MAX_HOSTNAME_LEN    = 128;
  MAX_DOMAIN_NAME_LEN = 128;
  MAX_SCOPE_ID_LEN    = 256;

  cERROR_BUFFER_TOO_SMALL = 603;
  cRAS_MaxEntryName       = 256;
  cRAS_MaxDeviceName      = 128;
  cRAS_MaxDeviceType      = 16;

  INTERNET_CONNECTION_MODEM           = 1;
  INTERNET_CONNECTION_LAN             = 2;
  INTERNET_CONNECTION_PROXY           = 4;
  INTERNET_CONNECTION_MODEM_BUSY      = 8;

  MAX_INTERFACE_NAME_LEN = 256;
  MAXLEN_PHYSADDR = 8;
  MAXLEN_IFDESCR = 256;

  MIB_IF_TYPE_OTHER = 1;
  MIB_IF_TYPE_ETHERNET = 6;
  MIB_IF_TYPE_TOKENRING = 9;
  MIB_IF_TYPE_FDDI = 15;
  MIB_IF_TYPE_PPP = 23;
  MIB_IF_TYPE_LOOPBACK = 24;
  MIB_IF_TYPE_SLIP = 28;

type
  ERasError = class(Exception);

  HRASConn = DWORD;
  PRASConn = ^TRASConn;
  TRASConn = record
    dwSize: DWORD;
    rasConn: HRASConn;
    szEntryName: array[0..cRAS_MaxEntryName] of Char;
    szDeviceType: array[0..cRAS_MaxDeviceType] of Char;
    szDeviceName: array [0..cRAS_MaxDeviceName] of Char;
  end;

  TRasEnumConnections = function(RASConn: PrasConn; { buffer to receive Connections data }
    var BufSize: DWORD;    { size in bytes of buffer }
    var Connections: DWORD { number of Connections written to buffer }
    ): Longint;
  stdcall;

  TConnectionType = (Modem, Lan, Proxy, ModemBuzy, None);
  SERVER_INFO_503 = record
    sv503_sessopens : Integer;
    sv503_sessvcs : Integer;
    sv503_opensearch : Integer;
    sv503_sizreqbuf : Integer;
    sv503_initworkitems : Integer;
    sv503_maxworkitems : Integer;
    sv503_rawworkitems : Integer;
    sv503_irpstacksize : Integer;
    sv503_maxrawbuflen : Integer;
    sv503_sessusers : Integer;
    sv503_sessconns : Integer;
    sv503_maxpagedmemoryusage : Integer;
    sv503_maxnonpagedmemoryusage : Integer;
    sv503_enablesoftcompat :BOOL;
    sv503_enableforcedlogoff :BOOL;
    sv503_timesource :BOOL;
    sv503_acceptdownlevelapis :BOOL;
    sv503_lmannounce :BOOL;
    sv503_domain : PWideChar;
    sv503_maxcopyreadlen : Integer;
    sv503_maxcopywritelen : Integer;
    sv503_minkeepsearch : Integer;
    sv503_maxkeepsearch : Integer;
    sv503_minkeepcomplsearch : Integer;
    sv503_maxkeepcomplsearch : Integer;
    sv503_threadcountadd : Integer;
    sv503_numblockthreads : Integer;
    sv503_scavtimeout : Integer;
    sv503_minrcvqueue : Integer;
    sv503_minfreeworkitems : Integer;
    sv503_xactmemsize : Integer;
    sv503_threadpriority : Integer;
    sv503_maxmpxct : Integer;
    sv503_oplockbreakwait : Integer;
    sv503_oplockbreakresponsewait : Integer;
    sv503_enableoplocks : BOOL;
    sv503_enableoplockforceclose : BOOL;
    sv503_enablefcbopens : BOOL;
    sv503_enableraw : BOOL;
    sv503_enablesharednetdrives : BOOL;
    sv503_minfreeconnections : Integer;
    sv503_maxfreeconnections : Integer;
  end;
  PSERVER_INFO_503 = ^SERVER_INFO_503;
  PNetResourceArray = ^TNetResourceArray;
  TNetResourceArray = array[0..100] of TNetResource;
  // TIPAddressString - store an IP address or mask as dotted decimal string
  PIPAddressString = ^TIPAddressString;
  PIPMaskString    = ^TIPAddressString;
  TIPAddressString = record
    _String: array[0..(4 * 4) - 1] of Char;
  end;
  TIPMaskString = TIPAddressString;
  // TIPAddrString - store an IP address with its corresponding subnet mask,
  // both as dotted decimal strings
  PIPAddrString = ^TIPAddrString;
  TIPAddrString = packed record
    Next: PIPAddrString;
    IpAddress: TIPAddressString;
    IpMask: TIPMaskString;
    Context: DWORD;
  end;
  // FIXED_INFO - the set of IP-related information which does not depend on DHCP
  PFixedInfo = ^TFixedInfo;
  TFixedInfo = packed record
    HostName: array[0..MAX_HOSTNAME_LEN + 4 - 1] of Char;
    DomainName: array[0..MAX_DOMAIN_NAME_LEN + 4 - 1] of Char;
    CurrentDnsServer: PIPAddrString;
    DnsServerList: TIPAddrString;
    NodeType: UINT;
    ScopeId: array[0..MAX_SCOPE_ID_LEN + 4 - 1] of Char;
    EnableRouting,
    EnableProxy,
    EnableDns: UINT;
  end;

  PULONG = ^ULONG;

  IP_ADDRESS_STRING = array[1..16] of Char;
  IP_MASK_STRING = array[1..16] of Char;

  PIP_ADDR_STRING = ^TIP_ADDR_STRING;
  TIP_ADDR_STRING = record
    Next: PIP_ADDR_STRING;
    IpAddress: IP_ADDRESS_STRING;
    IpMask: IP_MASK_STRING;
    Context: DWORD;
  end;


  PFIXED_INFO = ^TFIXED_INFO;
  TFIXED_INFO = record
    HostName: array[1..MAX_HOSTNAME_LEN + 4] of Char;
    DomainName: array[1..MAX_DOMAIN_NAME_LEN + 4] of Char;
    CurrentDnsServer: PIP_ADDR_STRING;
    DnsServerList: TIP_ADDR_STRING;
    NodeType: UINT;
    ScopeId: array[1..MAX_SCOPE_ID_LEN + 4] of Char;
    EnableRouting: UINT;
    EnableProxy: UINT;
    EnableDns: UINT;
  end;

  PMIB_IPADDRROW = ^TMIB_IPADDRROW;
  TMIB_IPADDRROW = packed record
    dwAddr: DWORD;
    dwIndex: DWORD;
    dwMask: DWORD;
    dwBCastAddr: DWORD;
    dwReasmSize: DWORD;
    unused1: SmallInt;
    wType: SmallInt;
  end;

  PMIB_IPADDRTABLE = ^TMIB_IPADDRTABLE;
  TMIB_IPADDRTABLE = record
    dwNumEntries: DWORD;
    table: array[0..0] of TMIB_IPADDRROW;
  end;

  PMIB_IFROW = ^TMIB_IFROW;
  TMIB_IFROW  = record
    wszName: array[1..MAX_INTERFACE_NAME_LEN] of WCHAR;
    dwIndex: DWORD;
    dwType: DWORD;
    dwMtu: DWORD;
    dwSpeed: DWORD;
    dwPhysAddrLen: DWORD;
    bPhysAddr: array[1..MAXLEN_PHYSADDR] of Byte;
    dwAdminStatus: DWORD;
    dwOperStatus: DWORD;
    dwLastChange: DWORD;
    dwInOctets: DWORD;
    dwInUcastPkts: DWORD;
    dwInNUcastPkts: DWORD;
    dwInDiscards: DWORD;
    dwInErrors: DWORD;
    dwInUnknownProtos: DWORD;
    dwOutOctets: DWORD;
    dwOutUcastPkts: DWORD;
    dwOutNUcastPkts: DWORD;
    dwOutDiscards: DWORD;
    dwOutErrors: DWORD;
    dwOutQLen: DWORD;
    dwDescrLen: DWORD;
    bDescr: array[1..MAXLEN_IFDESCR] of Byte;
  end;

  TDiscoveryCallback = reference to procedure(const ComputerName : string);


  TNetWorkInfo = class
  private
    fcurrentworkers : Integer;
    function GetMAC: string;
    function GetIP: string;
    function GetUser: string;
    function GetCompName: string;
    function GetDNSServ: TStringList;
    function GetNWComp: TStringList;
    function GetDN: String;
    function GetCIDR : string;
    function GetIntConnected: TConnectionType;
    function GetMask: string;
    function GetNetworkProperties(Adapter : Integer) : TMIB_IPADDRROW;
    procedure OnGetComputerTerminated(aSender : TObject);
  protected
    function  Get_MACAddress: string;
    function  GetIPAddress: String;
    function  GetDefaultNetWareUserName: string;
    function  GetDefaultComputerName: string;
    procedure GetDNSServers(AList: TStringList);
    function  CreateNetResourceList(ResourceType: DWord; NetResource: PNetResource; out Entries: DWord; out List: PNetResourceArray): Boolean;
    procedure ScanNetworkResources(ResourceType, DisplayType: DWord; List: TStrings);
    function  GetDomainName : string;
    function  InternetconnectionType: TConnectionType;
    function  RasConnectionCount : Integer;
  public
    function IsWrongIP(Ip: string): Boolean;
    function IPAddrToName(IPAddr: string): string;
    procedure GetNWCompARP(CallBack : TDiscoveryCallback);
    property CIDR : string read GetCIDR;
    property MACAddress  : string read GetMAC;
    property Mask        : string read GetMask;
    property IPAddress   : string read GetIP;
    property DefaultUser : string read GetUser;
    property ComputerName: string read GetCompName;
    property DNSServers  : TStringList read GetDNSServ;
    property DomainName  : String read GetDN;
    property InternetConnected: TConnectionType read GetIntConnected;
  published

  end;

  TDiscoveryWorker = class(TThread)
    private
      fCurrentIP : string;
      fCallback : TDiscoveryCallback;
    public
      constructor Create(CreateSuspended: Boolean; CurrentIP : string; Callback : TDiscoveryCallback);
      procedure Execute; override;
  end;


  function GetNetworkParams(pFixedInfo: PFixedInfo; pOutBufLen: PULONG): DWORD; stdcall;
  function NetServerGetInfo(serverName : PWideChar; level : Integer;var bufptr : Pointer) : Cardinal; stdcall; external 'NETAPI32.DLL';
  function NetApiBufferFree(buffer : Pointer) : Cardinal; stdcall; external 'NETAPI32.DLL';
  function InternetGetConnectedState(lpdwFlags: LPDWORD;dwReserved: DWORD): BOOL; stdcall; external 'WININET.DLL';

implementation

uses ActiveX, NB30;

const
  {$IFDEF MSWINDOWS}
  iphlpapidll = 'iphlpapi.dll';
  {$ENDIF}

  Const
   IFF_UP =		$00000001; //* Interface is up */
   IFF_BROADCAST =	$00000002; //* Broadcast is  supported */
   IFF_LOOPBACK = 	$00000004; //* this is loopback interface */
   IFF_POINTTOPOINT =     $00000008; //*this is point-to-point interface*/
   IFF_MULTICAST =	$00000010; //* multicast is supported */

  function GetNetworkParams; external iphlpapidll Name 'GetNetworkParams';

function GetIpAddrTable(IpAddrTable: PMIB_IPADDRTABLE; pdwSize: PULONG;
  Order: BOOL): DWORD; stdcall; external 'iphlpapi.dll' name 'GetIpAddrTable';

function GetIfEntry(pIfRow: PMIB_IFROW): DWORD;
  stdcall; external 'iphlpapi.dll' name 'GetIfEntry';


function PhysAddrToStr(PhysAddr: PByte; Len: DWORD): string;
begin
  Result:= EmptyStr;
  while Len > 1  do
  begin
    Result:= Result + IntToHex(PhysAddr^,2) + '-';
    inc(PhysAddr);
    dec(Len);
  end;
  if Len > 0 then
    Result:= Result + IntToHex(PhysAddr^,2);
end;

function IfTypeToStr(IfType: DWORD): string;
begin
  case ifType of
    MIB_IF_TYPE_ETHERNET: Result:= 'ETHERNET';
    MIB_IF_TYPE_TOKENRING: Result:= 'TOKENRING';
    MIB_IF_TYPE_FDDI: Result:= 'FDDI';
    MIB_IF_TYPE_PPP: Result:= 'PPP';
    MIB_IF_TYPE_LOOPBACK: Result:= 'LOOPBACK';
    MIB_IF_TYPE_SLIP: Result:= 'SLIP';
    else
      Result:= EmptyStr;
  end;
end;

function IpToStr(Ip: DWORD): string;
begin
  Result:= Format('%d.%d.%d.%d',
      [IP and $FF,(IP shr 8) and $FF,(IP shr 16) and $FF,(IP shr 24) and $FF]);
end;

function ReverseBits(anInt : Integer) : Integer;
var
  i : Integer;
begin
  result := 0;
  for i := 0 to (SizeOf(anInt) * 8 - 1) do
  begin
    result := (result shl 1) or (anInt and $01);
    anInt := anInt shr 1;
  end;
end;


{ TNetWorkInfo }

function TNetWorkInfo.IPAddrToName(IPAddr: string): string;
var
  SockAddrIn: TSockAddrIn;
  HostEnt: PHostEnt;
  WSAData: TWSAData;
  lasterr : Cardinal;
  a : string;
begin
  WSAStartup($101, WSAData);
  SockAddrIn.sin_addr.s_addr := IPv4ToIntReverse(IPAddr);
  HostEnt := gethostbyaddr(@SockAddrIn.sin_addr.S_addr, 4, AF_INET);
  if HostEnt <> nil then
    Result := StrPas(Hostent^.h_name)
  else
    Result := '';
end;

function TNetWorkInfo.RasConnectionCount: Integer;
var
  RasDLL:    HInst;
  Conns:     array[1..4] of TRasConn;
  RasEnums:  TRasEnumConnections;
  BufSize:   DWORD;
  NumConns:  DWORD;
  RasResult: Longint;
begin
  Result := 0;
  //Load the RAS DLL
  RasDLL := LoadLibrary('rasapi32.dll');
  if RasDLL = 0 then Exit;

  try
    RasEnums := GetProcAddress(RasDLL, 'RasEnumConnectionsA');
    if @RasEnums = nil then
      raise ERasError.Create('RasEnumConnectionsA not found in rasapi32.dll');

    Conns[1].dwSize := SizeOf(Conns[1]);
    BufSize         := SizeOf(Conns);

    RasResult := RasEnums(@Conns, BufSize, NumConns);

    if (RasResult = 0) or (Result = cERROR_BUFFER_TOO_SMALL) then Result := NumConns;
  finally
    FreeLibrary(RasDLL);
  end;
end;

function TNetWorkInfo.GetDomainName : string;
var
  err : Integer;
  buf : pointer;
  fDomainName: string;
  wServerName : WideString;
begin
  wServerName := GetDefaultComputerName;
  err := NetServerGetInfo (PWideChar (wServerName), 503, buf);
  if err = 0 then
  try
    fDomainName := PSERVER_INFO_503 (buf)^.sv503_domain;
  finally
    NetAPIBufferFree (buf)
  end;
  result := fDomainName;
end;

function TNetWorkInfo.IsWrongIP(Ip: string): Boolean;
const
  Z = ['0'..'9', '.'];
var
  I, J, P: Integer;
  W: string;
begin
  Result := False;
  if (Length(Ip) > 15) or (Ip[1] = '.') then Exit;
  I := 1;
  J := 0;
  P := 0;
  W := '';
  repeat
    if (Ip[I] in Z) and (J < 4) then
    begin
      if Ip[I] = '.' then
      begin
        Inc(P);
        J := 0;
        try
          StrToInt(Ip[I + 1]);
        except
          Exit;
        end;
        W := '';
      end
      else
      begin
        W := W + Ip[I];
        if (StrToInt(W) > 255) or (Length(W) > 3) then Exit;
        Inc(J);
      end;
    end
    else
      Exit;
    Inc(I);
  until I > Length(Ip);
  if P < 3 then Exit;
  Result := True;
end;


procedure TNetWorkInfo.OnGetComputerTerminated(aSender: TObject);
begin
  Dec(fcurrentworkers);
end;

function TNetWorkInfo.CreateNetResourceList(ResourceType: DWord; NetResource: PNetResource;
                              out Entries: DWord; out List: PNetResourceArray): Boolean;
var
  EnumHandle: THandle;
  BufSize: DWord;
  Res: DWord;
begin
  Result := False;
  List := Nil;
  Entries := 0;
  if WNetOpenEnum(RESOURCE_GLOBALNET,
                  ResourceType,
                  0,
                  NetResource,
                  EnumHandle) = NO_ERROR then begin
    try
      BufSize := $4000;  // 16 kByte
      GetMem(List, BufSize);
      try
        repeat
          Entries := DWord(-1);
          FillChar(List^, BufSize, 0);
          Res := WNetEnumResource(EnumHandle, Entries, List, BufSize);
          if Res = ERROR_MORE_DATA then
          begin
            ReAllocMem(List, BufSize);
          end;
        until Res <> ERROR_MORE_DATA;

        Result := Res = NO_ERROR;
        if not Result then
        begin
          FreeMem(List);
          List := Nil;
          Entries := 0;
        end;
      except
        FreeMem(List);
        raise;
      end;
    finally
      WNetCloseEnum(EnumHandle);
    end;
  end;
end;

procedure TNetWorkInfo.ScanNetworkResources(ResourceType, DisplayType: DWord; List: TStrings);
  procedure ScanLevel(NetResource: PNetResource);
  var
    Entries: DWord;
    NetResourceList: PNetResourceArray;
    i: Integer;
  begin
    if CreateNetResourceList(ResourceType, NetResource, Entries, NetResourceList) then try
      for i := 0 to Integer(Entries) - 1 do
      begin
        if (DisplayType = RESOURCEDISPLAYTYPE_GENERIC) or
          (NetResourceList[i].dwDisplayType = DisplayType) then begin
          List.AddObject(NetResourceList[i].lpRemoteName, Pointer(NetResourceList[i].dwDisplayType));
        end;
        if (NetResourceList[i].dwUsage and RESOURCEUSAGE_CONTAINER) <> 0 then
          ScanLevel(@NetResourceList[i]);
      end;
    finally
      FreeMem(NetResourceList);
    end;
  end;
begin
  ScanLevel(Nil);
end;

procedure TNetWorkInfo.GetDNSServers(AList: TStringList);
var
  pFI: PFixedInfo;
  pIPAddr: PIPAddrString;
  OutLen: Cardinal;
begin
  AList.Clear;
  OutLen := SizeOf(TFixedInfo);
  GetMem(pFI, SizeOf(TFixedInfo));
  try
    if GetNetworkParams(pFI, @OutLen) = ERROR_BUFFER_OVERFLOW then
    begin
      ReallocMem(pFI, OutLen);
      if GetNetworkParams(pFI, @OutLen) <> NO_ERROR then Exit;
    end;
    // If there is no network available there may be no DNS servers defined
    if pFI^.DnsServerList.IpAddress._String[0] = #0 then Exit;
    // Add first server
    AList.Add(pFI^.DnsServerList.IpAddress._String);
    // Add rest of servers
    pIPAddr := pFI^.DnsServerList.Next;
    while Assigned(pIPAddr) do
    begin
      AList.Add(pIPAddr^.IpAddress._String);
      pIPAddr := pIPAddr^.Next;
    end;
  finally
    FreeMem(pFI);
  end;
end;

function TNetWorkInfo.GetDefaultNetWareUserName: string;
var ipNam: PChar;
    Size: DWord;
begin
   ipNam := nil;
   Size := 128;
   try
      Result   := '';
      GetMem(ipNam, Size);
      if GetUserName(ipNam, Size)
      then Result := UpperCase(TRIM(strPas(ipNam)))
      else Result := '?';
   finally
      FreeMem(ipNam, 10);
   end;
end;

function TNetWorkInfo.GetDefaultComputerName: string;
var ipNam: PChar;
    Size: DWord;
begin
   ipNam := nil;
   Size := MAX_COMPUTERNAME_LENGTH + 1;
   try
      Result := '';
      GetMem(ipNam, Size);
      if GetComputerName(ipNam, Size)
      then Result := UpperCase(TRIM(strPas(ipNam)))
      else Result := '?';
   finally
      FreeMem(ipNam, 10);
   end;
end;

function TNetWorkInfo.Get_MACAddress: string;
var
  NCB: PNCB;
  Adapter: PAdapterStatus;

  URetCode: PChar;
  RetCode: AnsiChar;
  I: integer;
  Lenum: PlanaEnum;
  _SystemID: string;
  TMPSTR: string;
begin
  Result    := '';
  _SystemID := '';
  Getmem(NCB, SizeOf(TNCB));
  Fillchar(NCB^, SizeOf(TNCB), 0);

  Getmem(Lenum, SizeOf(TLanaEnum));
  Fillchar(Lenum^, SizeOf(TLanaEnum), 0);

  Getmem(Adapter, SizeOf(TAdapterStatus));
  Fillchar(Adapter^, SizeOf(TAdapterStatus), 0);

  Lenum.Length    := chr(0);
  NCB.ncb_command := chr(NCBENUM);
  NCB.ncb_buffer  := Pointer(Lenum);
  NCB.ncb_length  := SizeOf(Lenum);
  RetCode         := Netbios(NCB);

  i := 0;
  repeat
    Fillchar(NCB^, SizeOf(TNCB), 0);
    Ncb.ncb_command  := chr(NCBRESET);
    Ncb.ncb_lana_num := lenum.lana[I];
    RetCode          := Netbios(Ncb);

    Fillchar(NCB^, SizeOf(TNCB), 0);
    Ncb.ncb_command  := chr(NCBASTAT);
    Ncb.ncb_lana_num := lenum.lana[I];
    // Must be 16
    Ncb.ncb_callname := '*               ';

    Ncb.ncb_buffer := Pointer(Adapter);

    Ncb.ncb_length := SizeOf(TAdapterStatus);
    RetCode        := Netbios(Ncb);
    //---- calc _systemId from mac-address[2-5] XOR mac-address[1]...
    if (RetCode = chr(0)) or (RetCode = chr(6)) then
    begin
      _SystemId := IntToHex(Ord(Adapter.adapter_address[0]), 2) + '-' +
        IntToHex(Ord(Adapter.adapter_address[1]), 2) + '-' +
        IntToHex(Ord(Adapter.adapter_address[2]), 2) + '-' +
        IntToHex(Ord(Adapter.adapter_address[3]), 2) + '-' +
        IntToHex(Ord(Adapter.adapter_address[4]), 2) + '-' +
        IntToHex(Ord(Adapter.adapter_address[5]), 2);
    end;
    Inc(i);
  until (I >= Ord(Lenum.Length)) or (_SystemID <> '00-00-00-00-00-00');
  FreeMem(NCB);
  FreeMem(Adapter);
  FreeMem(Lenum);
  Result := _SystemID;
end;

function TNetWorkInfo.GetIPAddress: String;
type
   TaPInAddr = Array[0..10] of PInAddr;
   PaPInAddr = ^TaPInAddr;
var
   phe: PHostEnt;
   pptr: PaPInAddr;
   Buffer: Array[0..63] of AnsiChar;
   I: Integer;
   GInitData: TWSAData;
begin
   WSAStartup($101, GInitData);
   Result := '';
   GetHostName(Buffer, SizeOf(Buffer));
   phe := GetHostByName(buffer);
   if phe = nil then Exit;
   pPtr := PaPInAddr(phe^.h_addr_list);
   I := 0;
   while pPtr^[I] <> nil do
   begin
      Result := inet_ntoa(pptr^[I]^);
      Inc(I);
   end;
   WSACleanup;
end;

function TNetWorkInfo.GetMAC: string;
begin
  Result := Get_MACAddress ;
end;

function TNetWorkInfo.GetMask: string;
begin
  Result := IpToStr(GetNetworkProperties(0).dwMask);
end;

function TNetWorkInfo.GetIP: string;
begin
    Result := GetIPAddress;
end;

function TNetWorkInfo.GetUser: string;
begin
    Result := GetDefaultNetWareUserName;
end;

function TNetWorkInfo.GetCIDR: string;
begin
  //TODO Get CIDR from the first adapter.
end;

function TNetWorkInfo.GetCompName: string;
begin
    Result :=  GetDefaultComputerName;
end;

function TNetWorkInfo.GetDNSServ: TStringList;
var
   DNSList : TStringList;
begin
   DNSList := TStringList.Create;
   GetDNSServers(DNSList);
   Result := DNSList;
end;

function TNetWorkInfo.GetNetworkProperties(Adapter : Integer) : TMIB_IPADDRROW;
var
  OutBufLen: ULONG;
  IpAddr: PIP_ADDR_STRING;
  IfRow: TMIB_IFROW;
  Table: PMIB_IPADDRTABLE;
  Size: DWORD;
  i: Integer;
begin
  // Ip Address Table
  GetMem(Table, Sizeof(TMIB_IPADDRTABLE));
  try
    Size:= Sizeof(TMIB_IPADDRTABLE);
    if GetIpAddrTable(Table, @Size,  FALSE) =  ERROR_INSUFFICIENT_BUFFER then
    begin
      FreeMem(Table);
      GetMem(Table,Size);
    end;
    FillChar(Table^,Size,0);
    if GetIpAddrTable(Table, @Size,  FALSE) =  NO_ERROR then
    begin
      for i:= 0 to Table.dwNumEntries - 1 do
      begin
        if Adapter = i then result := Table.Table[i];
        Exit;
      end;
    end;
  finally
    Freemem(Table);
  end;
end;

function TNetWorkInfo.GetNWComp: TStringList;
var
   CompList : TStringList;
begin
   CompList := TStringList.Create;
   ScanNetworkResources(RESOURCETYPE_DISK, RESOURCEDISPLAYTYPE_SERVER,CompList);
   Result := CompList;
end;

procedure TNetWorkInfo.GetNWCompARP(CallBack : TDiscoveryCallback);
var
  localIP : string;
  localMask : string;
  highip : TArray<string>;
  lowip :  TArray<string>;
  templowip : string;
  temphighip : string;
  highiptemp : integer;
  currentip : integer;
const
  TOTALWORKERS : Integer = 32;
begin
  fcurrentworkers := 0;
  localIP := GetIPAddress;
  localMask := GetMask;
  GetIPRange(localIP, localMask, templowip, temphighip);
  if (templowip <> '') and (temphighip <> '') then
  begin
    lowip := templowip.Split(['.']);
    highip := temphighip.Split(['.']);
    if (High(lowip) = 3) and (High(highip) = 3) then
    begin
      currentip := lowip[3].ToInteger;
      highiptemp := highip[3].ToInteger;
      while currentip <= highiptemp do
      begin
        if currentip = 0 then Inc(currentip);
        while fcurrentworkers = TOTALWORKERS do
        begin
          Sleep(100);
        end;
        if fcurrentworkers <= TOTALWORKERS then
        begin
          inc(fcurrentworkers);
          with TDiscoveryWorker.Create(True, Format('%s.%s.%s.%d', [lowip[0], lowip[1], lowip[2], currentip]), CallBack) do
          begin
            OnTerminate := OnGetComputerTerminated;
            Start;
          end;
        end;
        Inc(currentip);
      end;
    end;
  end;
end;

function TNetWorkInfo.GetDN: String;
begin
   Result := GetDomainName;
end;

function TNetWorkInfo.GetIntConnected: TConnectionType;
begin
  Result := InternetconnectionType;
end;

function TNetWorkInfo.InternetconnectionType: TConnectionType;
var
   dwConnectionTypes: Integer;
   Res : boolean;
begin
   Res := InternetGetConnectedState(@dwConnectionTypes, 0);

   if (dwConnectionTypes and INTERNET_CONNECTION_MODEM )= INTERNET_CONNECTION_MODEM then
   begin
      Result := Modem;
      Exit;
   end;

   if (dwConnectionTypes and  INTERNET_CONNECTION_LAN  )= INTERNET_CONNECTION_LAN then
   begin
      Result := Lan;
      Exit;
   end;

   if (dwConnectionTypes and  INTERNET_CONNECTION_PROXY) = INTERNET_CONNECTION_PROXY then
   begin
      Result := Proxy;
      Exit;
   end;
   Result := None;
end;

function IPAddrToName(const IPAddr: string): string;
var
  SockAddrIn: TSockAddrIn;
  HostEnt: PHostEnt;
  WSAData: TWSAData;
begin
  WSAStartup($101, WSAData);
  SockAddrIn.sin_addr.s_addr:=IPv4ToIntReverse(IPAddr);
  HostEnt:= GetHostByAddr(@SockAddrIn.sin_addr.S_addr, 4, AF_INET);
  if HostEnt<>nil then
  begin
    Result:=StrPas(Hostent^.h_name)
  end
  else
  begin
    Result:='';
  end;
  WSACleanup;
end;
{ TDiscoveryWorker }

constructor TDiscoveryWorker.Create(CreateSuspended: Boolean; CurrentIP : string; CallBack : TDiscoveryCallback);
begin
  inherited Create(CreateSuspended);
  FreeOnTerminate := True;
  fCurrentIP := CurrentIP;
  fCallback := CallBack;
end;

procedure TDiscoveryWorker.Execute;
var
  name : string;
  ip : Integer;
begin
  name := IPAddrToName(fCurrentIP);
  tthread.Synchronize(nil,
  procedure
  begin
    if not name.IsEmpty and Assigned(fCallback) then fCallback(name);
  end
  );
end;

end.
