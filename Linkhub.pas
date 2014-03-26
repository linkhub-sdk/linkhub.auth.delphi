(*
*=================================================================================
* Unit for develop interoperation with Linkhub APIs.
* Functionalities are authentication for Linkhub api products, and to support
* several base infomation(ex. Remain point).
*
* This module uses synapse library.( http://www.ararat.cz/synapse/doku.php/ )
* It's full open source library, free to use include commercial application.
* If you wish to donate that, visit their site.
* So, before using this module, you need to install synapse by user self.
* You can refer their site or detailed infomation about installation is available
* from below our site. We appreciate your visiting.
*
* For strongly secured communications, this module uses SSL/TLS with OpenSSL.
* So You need two dlls (libeay32.dll and ssleay32.dll) from OpenSSL. You can
* get it from Fulgan. ( http://indy.fulgan.com/SSL/ ) We recommend i386_win32 version.
* And also, dlls must be released with your executions. That's the drawback of this
* module, but we acommplished higher security level against that.
*
* http://www.linkhub.co.kr
* Author : Kim Seongjun (pallet027@gmail.com)
* Written : 2014-03-22

* Thanks for your interest. 
*=================================================================================
*)
unit Linkhub;

interface

uses
  Windows, SysUtils, Classes, HTTPSend , ssl_openssl, synachar, synautil, synacode;

const
  ServiceURL_REAL = 'https://api.linkhub.co.kr';
  ServiceURL_TEST = 'https://demo.innopost.com';
  APIVersion = '1.0';

type
  TToken = class;
  ArrayOfString = Array Of String;
  
  TAuth = class
  private
    FIsTest    : boolean;
    FPartnerID : string;
    FSecretKey : string;
  public
    constructor  Create(PartnerID : string; SecretKey : string);
    function getToken(ServiceID : String; access_id : String; scope : array Of String) : TToken; overload;
    function getToken(ServiceID : String; access_id : String; scope : array Of String; forwardIP : String) : TToken; overload;
    function getBalance(bearerToken : String; ServiceID : String) : Double;
    function getPartnerBalance(bearerToken : String; ServiceID : String) : Double;
  published
    property IsTest : boolean read FIsTest write FIsTest;
  end;

  TToken = class
  private
        Fsession_token : string;
        FserviceID : string;
        FpartnerID : string;
        Fusercode : string;
        Fexpiration : string;
        Fipaddress : string;
        Fscope : ArrayOfString;
  public
      property session_token : string read Fsession_token write Fsession_token;
      property serviceID : string read FserviceID write FserviceID;
      property partnerID : string read FpartnerID write FpartnerID;
      property usercode : string read Fusercode write Fusercode;
      property expiration : string read Fexpiration write Fexpiration;
      property ipaddress : string read Fipaddress write Fipaddress;
      property scope : ArrayOfString read Fscope write Fscope;

  end;

  ELinkhubException  = class(Exception)
  private
    FCode : LongInt;
  public
    constructor Create(code : LongInt; Message : String);
  published
    property code : LongInt read FCode write FCode;
  end;

  function NowUTC: TDateTime;
  function UTCToDate(strDT : string) : TDateTime;
  function StreamToString(Stream: TStream): WideString;
  function Utf8ToUnicode(Dest: PWideChar; MaxDestChars: Cardinal; Source: PChar; SourceBytes: Cardinal): Cardinal;
  function UnicodeToUtf8(Dest: PChar; MaxDestBytes: Cardinal; Source: PWideChar; SourceChars: Cardinal): Cardinal;
  function getJSonString(Data : String; Key : String) : String;
  function getJSonInteger(Data : String; Key : String) : Integer;
  function getJSonFloat(Data : String; Key : String) : Double;
  function getJSonList(Data : String; Key : String) : ArrayOfString;
  function ParseJsonList(inputJson : String) : ArrayOfString;
  function IfThen(condition :boolean; trueVal :String ; falseVal : String) : string;
implementation

constructor ELinkhubException.Create(code : LongInt; Message : String);
begin
inherited Create(Message);
FCode := code;
end;

constructor TAuth.Create(PartnerID : string; SecretKey : string);
begin
     FPartnerID := PartnerID;
     FSecretKey := SecretKey;
     FIsTest := false;
end;

function TAuth.getToken(ServiceID : String; access_id : String; scope : array Of String) : TToken;
begin
        result := getToken(ServiceID,access_id,scope,'');
end;

function TAuth.getToken(ServiceID : String; access_id : String; scope : array Of String; forwardIP : String) : TToken;
var
  HTTP: THTTPSend;
  xdate : String;
  target : String;
  postdata : String;
  bearerToken : String;
  url   : String;
  i : Integer;
  response : string;
begin

  Result := TToken.Create;
  HTTP := THTTPSend.Create;
  HTTP.Sock.SSLDoConnect;

  
  xdate := FormatDateTime('yyyy-mm-dd''T''HH:mm:ss.zzz''Z''',NowUTC);
  HTTP.Headers.Add('x-lh-date: ' + xdate);
  HTTP.Headers.Add('x-lh-version: ' + APIVersion);

  if forwardIP <> '' then HTTP.Headers.Add('x-lh-forwarded: ' + forwardIP);


  postdata := '"access_id":"'+access_id+'"';

  if length(scope) > 0 then
  begin
    postdata := postdata + ',"scope":[';
    for i := 0 to length(scope)-1 do
    begin
         postdata := postdata + '"' + scope[i] + '"';
         if i < length(scope) -1 then
         begin
            postdata := postdata + ',';
         end
         else
         begin
           postdata := postdata + ']';
         end
    end;
  end;

  postdata := '{' + postdata + '}';

  target := 'POST' + #10;
  target := target + EncodeBase64(md5(postdata)) + #10;
  target := target + xdate + #10;
  if forwardIP <> '' then target := target + forwardIP + #10;
  target := target + APIVersion + #10;
  target := target + '/'+ServiceID+'/Token';

  bearerToken := EncodeBase64(HMAC_SHA1(target,DecodeBase64( FSecretKey)));

  HTTP.Headers.Add('Authorization: LINKHUB '+FPartnerID+' ' + bearerToken);

  if FIsTest then url := ServiceURL_TEST + '/' + ServiceID + '/Token'
             else url := ServiceURL_REAL + '/' + ServiceID + '/Token';

  try

      HTTP.Document.CopyFrom(TStringStream.Create(postdata), 0);
      HTTP.MimeType := 'Application/json';
      if HTTP.HTTPMethod('POST', url) then
      begin
         if HTTP.ResultCode <> 200 then
         begin
                response := StreamToString(HTTP.Document);
                raise ELinkhubException.Create(getJSonInteger(response,'code'),getJSonString(response,'message'));
         end;
         response := StreamToString(HTTP.Document);



         Result.session_token := getJSonString(response,'session_token');
         Result.serviceID := getJSonString(response,'serviceID');
         Result.partnerID := getJSonString(response,'partnerID');
         Result.usercode := getJSonString(response,'usercode');
         Result.ipaddress := getJSonString(response,'ipaddress');
         Result.expiration := getJSonString(response,'expiration');
      end
      else
      begin
        if HTTP.ResultCode <> 200 then
        begin
                raise ELinkhubException.Create(-99999999,HTTP.ResultString);
        end;
      end;

  finally
        HTTP.Free;
  end;

end;

function TAuth.getBalance(bearerToken : String; ServiceID : String) : Double;
var
  HTTP: THTTPSend;
  url   : String;
  response : string;
begin
  result := 0;
  HTTP := THTTPSend.Create;
  HTTP.Sock.SSLDoConnect;

  HTTP.Headers.Add('Authorization: Bearer ' + bearerToken);

  if FIsTest then url := ServiceURL_TEST + '/' + ServiceID + '/Point'
             else url := ServiceURL_REAL + '/' + ServiceID + '/Point';

  try

      if HTTP.HTTPMethod('GET', url) then
      begin
         if HTTP.ResultCode <> 200 then
         begin
                response := StreamToString(HTTP.Document);
                raise ELinkhubException.Create(getJSonInteger(response,'code'),getJSonString(response,'message'));
         end;

         response := StreamToString(HTTP.Document);
         result := strToFloat(getJSonString(response,'remainPoint'));
      end
      else
      begin
        if HTTP.ResultCode <> 200 then
        begin
                raise ELinkhubException.Create(-99999999,HTTP.ResultString);
        end;
      end;

  finally
        HTTP.Free;
  end;

end;

function TAuth.getPartnerBalance(bearerToken : String; ServiceID : String) : Double;
var
  HTTP: THTTPSend;
  url   : String;
  response : string;
begin
  result := -1;
  HTTP := THTTPSend.Create;
  HTTP.Sock.SSLDoConnect;

  HTTP.Headers.Add('Authorization: Bearer ' + bearerToken);

  if FIsTest then url := ServiceURL_TEST + '/' + ServiceID + '/PartnerPoint'
             else url := ServiceURL_REAL + '/' + ServiceID + '/PartnerPoint';

  try

      if HTTP.HTTPMethod('GET', url) then
      begin
         if HTTP.ResultCode <> 200 then
         begin
                response := StreamToString(HTTP.Document);
                raise ELinkhubException.Create(getJSonInteger(response,'code'),getJSonString(response,'message'));
         end;

         response := StreamToString(HTTP.Document);
         result := StrToFloat(getJSonString(response,'remainPoint'));
      end
      else
      begin
        if HTTP.ResultCode <> 200 then
        begin
                raise ELinkhubException.Create(-99999999,HTTP.ResultString);
        end;
      end;

  finally
        HTTP.Free;
  end;

end;

function NowUTC: TDateTime;
var
        system_datetime: TSystemTime;
begin
        GetSystemTime(system_datetime);
        Result := SystemTimeToDateTime(system_datetime);
end;

function StreamToString(Stream: TStream): WideString;
var
        ms: TMemoryStream;
        byteTemp : Array of Byte;
begin
        ms := TMemoryStream.Create;
        try
                ms.LoadFromStream(Stream);
                SetLength(byteTemp,ms.size * 3);
                Utf8ToUnicode(@byteTemp[0],Length(byteTemp),ms.memory,ms.Size);
                Result := Trim(WideString(byteTemp));
        finally
                ms.Free;
        end;
end;

function Utf8ToUnicode(Dest: PWideChar; MaxDestChars: Cardinal; Source: PChar; SourceBytes: Cardinal): Cardinal;
	var
		i, count: Cardinal;
		c: Byte;
		wc: Cardinal;
	begin
		if Source = nil then
		begin
			Result := 0;
			Exit;
		end;
		Result := Cardinal(-1);
		count := 0;
		i := 0;
		if Dest <> nil then
		begin
			while (i < SourceBytes) and (count < MaxDestChars) do
			begin
				wc := Cardinal(Source[i]);
				Inc(i);
				if (wc and $80) <> 0 then
				begin
					if i >= SourceBytes then Exit;          // incomplete multibyte char
					wc := wc and $3F;
					if (wc and $20) <> 0 then
					begin
						c := Byte(Source[i]);
						Inc(i);
						if (c and $C0) <> $80 then Exit;      // malformed trail byte or out of range char
						if i >= SourceBytes then Exit;        // incomplete multibyte char
						wc := (wc shl 6) or (c and $3F);
					end;
					c := Byte(Source[i]);
					Inc(i);
					if (c and $C0) <> $80 then Exit;       // malformed trail byte

					Dest[count] := WideChar((wc shl 6) or (c and $3F));
				end
				else
					Dest[count] := WideChar(wc);
				Inc(count);
			end;
			if count >= MaxDestChars then count := MaxDestChars-1;
			Dest[count] := #0;
		end
		else
		begin
			while (i < SourceBytes) do
			begin
				c := Byte(Source[i]);
				Inc(i);
				if (c and $80) <> 0 then
				begin
					if i >= SourceBytes then Exit;          // incomplete multibyte char
					c := c and $3F;
					if (c and $20) <> 0 then
					begin
						c := Byte(Source[i]);
						Inc(i);
						if (c and $C0) <> $80 then Exit;      // malformed trail byte or out of range char
						if i >= SourceBytes then Exit;        // incomplete multibyte char
					end;
					c := Byte(Source[i]);
					Inc(i);
					if (c and $C0) <> $80 then Exit;       // malformed trail byte
				end;
				Inc(count);
			end;
		end;
		Result := count+1;
	end;

function UnicodeToUtf8(Dest: PChar; MaxDestBytes: Cardinal; Source: PWideChar; SourceChars: Cardinal): Cardinal;
var
	i, count: Cardinal;
	c: Cardinal;
begin
	Result := 0;
	if Source = nil then Exit;
	count := 0;
	i := 0;
	if Dest <> nil then
	begin
		while (i < SourceChars) and (count < MaxDestBytes) do
		begin
			c := Cardinal(Source[i]);
			Inc(i);
			if c <= $7F then
			begin
				Dest[count] := Char(c);
				Inc(count);
			end
			else if c > $7FF then
			begin
				if count + 3 > MaxDestBytes then
					break;
				Dest[count] := Char($E0 or (c shr 12));
				Dest[count+1] := Char($80 or ((c shr 6) and $3F));
				Dest[count+2] := Char($80 or (c and $3F));
				Inc(count,3);
			end
			else //  $7F < Source[i] <= $7FF
			begin
				if count + 2 > MaxDestBytes then
					break;
				Dest[count] := Char($C0 or (c shr 6));
				Dest[count+1] := Char($80 or (c and $3F));
				Inc(count,2);
			end;
		end;
		if count >= MaxDestBytes then count := MaxDestBytes-1;
		Dest[count] := #0;
	end
	else
	begin
		while i < SourceChars do
		begin
			c := Integer(Source[i]);
			Inc(i);
			if c > $7F then
			begin
				if c > $7FF then
					Inc(count);
				Inc(count);
			end;
			Inc(count);
		end;
	end;
	Result := count+1;  // convert zero based index to byte count
end;


function getJSonString(Data : String; Key : String) : String;
var
        StartPos : integer;
	EndPos : integer;
begin
	StartPos := Pos('"' + Key + '":',Data);

        if StartPos = 0 then
        begin
                Result := '';
        end
        else
        begin
                StartPos := StartPos  + Length('"' + Key + '":');
                if Copy(Data,StartPos,1) = '"' then StartPos := StartPos + 1;

                //이건좀 문제가 있음. value안에 '"'가 있을경우 잘리는 문제가 있음.
                EndPos := PosFrom('"',Data,StartPos);

                while Copy(Data,EndPos-1,1) = '\' do
                begin
                         EndPos := PosFrom('"',Data,EndPos+1);
                end;

                if StartPos = EndPos then begin
                        Result := '';
                end
                else begin
                        Result := Copy(Data,StartPos,EndPos-StartPos);
                end;
        end;
end;

function getJSonInteger(Data : String; Key : String) : Integer;
var
        StartPos : integer;
	EndPos : integer;
        val : String;
begin
	StartPos := Pos('"' + Key + '":',Data);

        if StartPos = 0 then
        begin
                Result := 0;
        end
        else
        begin
                StartPos := StartPos  + Length('"' + Key + '":');
                if Copy(Data,StartPos,1) = '"' then StartPos := StartPos + 1;

                EndPos := PosFrom(',',Data,StartPos);
                if EndPos = 0 then EndPos := posFrom('}',Data,StartPos);
                if EndPos = 0 then Raise ELinkhubException.Create(-99999999,'malformed json');

                EndPos := EndPos;

                if StartPos = EndPos then begin
                        Result := 0;
                end
                else begin
                        val := Copy(Data,StartPos,EndPos-StartPos);
                        result := StrToInt(val);
                end;
        end;
end;

function getJSonFloat(Data : String; Key : String) : Double;
var
        StartPos : integer;
	EndPos : integer;
        val : String;
begin
	StartPos := Pos('"' + Key + '":',Data);

        if StartPos = 0 then
        begin
                Result := 0;
        end
        else
        begin
                StartPos := StartPos  + Length('"' + Key + '":');
                if Copy(Data,StartPos,1) = '"' then StartPos := StartPos + 1;

                EndPos := PosFrom(',',Data,StartPos);
                if EndPos = 0 then EndPos := posFrom('}',Data,StartPos);
                if EndPos = 0 then Raise ELinkhubException.Create(-99999999,'malformed json');

                EndPos := EndPos;

                if StartPos = EndPos then begin
                        Result := 0;
                end
                else begin
                        val := Copy(Data,StartPos,EndPos-StartPos);
                        result := StrToFloat(val);
                end;
        end;
end;

function getJSonList(Data : String; Key : String) : ArrayOfString;
var
        StartPos : integer;
	EndPos : integer;
        targetJson : String;
begin
	StartPos := Pos('"' + Key + '":',Data);

        if StartPos = 0 then
        begin
                targetJson := '';
        end
        else
        begin
                StartPos := StartPos  + Length('"' + Key + '":');
                if Copy(Data,StartPos,1) = '[' then StartPos := StartPos + 1;

                //이건좀 문제가 있음. value안에 ','가 있을경우 잘리는 문제가 있음.
                EndPos := PosFrom(']',Data,StartPos);
                //문서안에 '}'가 있으면 문제가 있어버림.
                if EndPos = 0 then EndPos := PosFrom('}',Data,StartPos);
                if EndPos = 0 then raise ELinkhubException.Create(-99999999,'JSON PARSING ERROR');

                if Copy(Data,EndPos-1,1) = '"' then EndPos := EndPos - 1;

                if StartPos = EndPos then begin
                        targetJson := '';
                end
                else begin
                        targetJson := Copy(Data,StartPos,EndPos-StartPos);
                        result:= ParseJsonList(targetJson);
                end;
        end;
end;

function ParseJsonList(inputJson : String) : ArrayOfString;
var
        i,level,startpos,endpos,count : integer;

begin
        startpos := 0;
        count := 0;
        SetLength(result,count);
        level := 0;

        for i:=0 to Length(inputJson) do
        begin
                if inputJson[i] = '{' then
                begin
                    level := level + 1;
                    if level  = 1 then startpos := i;
                end;

                if inputJson[i] = '}' then
                begin
                    level := level - 1;
                    if level  = 0 then begin
                         count := count + 1;
                         SetLength(result,count);
                         endpos := i;
                         result[count - 1 ] := Copy(inputJson,startpos,endpos-startpos + 1);
                    end
                end;
        end;
end;

function IfThen(condition :boolean; trueVal :String ; falseVal : String) : string;
begin
    if condition then result := trueVal else result := falseVal;
end;


function UTCToDate(strDT : string) : TDateTime;
var
  // Delphi settings save vars
  ShortDF, ShortTF : string;
  TS, DS : char;
  // conversion vars
  dd, tt, ddtt: TDateTime;
begin
  
  // save Delphi settings
  DS := DateSeparator;
  TS := TimeSeparator;
  ShortDF := ShortDateFormat;
  ShortTF := ShortTimeFormat;

  // set Delphi settings for string to date/time
  DateSeparator := '-';
  ShortDateFormat := 'yyyy-mm-dd';
  TimeSeparator := ':';
  ShortTimeFormat := 'hh:mm:ss';

  // convert test string to datetime
  try

    dd := StrToDate( Copy(strDT, 1, Pos('T',strDT)-1) );
    tt := StrToTime( Copy(strDT, Pos('T',strDT)+1, 8) );
    ddtt := trunc(dd) + frac(tt);

  except
    on EConvertError do
       raise ELinkhubException.Create(-99999999,'만료일 형식변환 실패.');
  end;

  //TimeZone

  ddtt := ((ddtt * 1440) + TimeZoneBias) /1440;

  // restore Delphi settings
  DateSeparator := DS;
  ShortDateFormat := ShortDF;
  TimeSeparator := TS;
  ShortTimeFormat := ShortTF;

  result := ddtt;
end;

end.
