program GoogleMX;

{$APPTYPE CONSOLE}

{$R *.res}
{$R Resources.res}

uses
    System.Variants,
    System.SysUtils,
    System.StrUtils,
    System.Classes,
    IdDNSResolver,
    ShellApi,
    Windows,
    ActiveX,
    XMLIntf,
    XMLDoc,
    MSXML;

type
    ServiceStatus = ( StatusOpen, StatusFiltered, StatusClosed );

    Service = record
        port:     Word;
        protocol,
        name,
        status,
        info:     String;
    end;

    Host = record
        Services:   Array of Service;
        IP,
        DNSname,
        PTRname,
        MailServer: String;
    end;

    Domain = record
        Name,
        MailServer: String;
        Hosts:      Array of Host;
    end;

    DomainArray = Array of Domain;

const
    nInputFile =  'nmap_input.txt';
    nOutputFile = 'nmap_output.xml';
    knownMTA:     array[0..6] of string = ('Exchange', 'Lotus', 'MDaemon', 'Postfix', 'Exim', 'Dovecot', 'hMail');
    fullMTANames: array[0..6] of string = ('Microsoft Exchange Server', 'IBM Lotus Domino', 'MDaemon Mail Server', 'Postfix', 'Exim', 'Dovecot', 'hMailServer');
    ExtraDomains: array[0..9] of string = ('pop', 'pop3', 'imap', 'imap4', 'pops', 'pop3s', 'imaps', 'imap4s', 'mail', 'webmail');

var
    Domains: DomainArray;

procedure LoadDomains;
var
    iFile: TextFile;
begin
    if not FileExists( 'prova.txt' ) then // TODO: Stabilire il nome del file di input
    begin
        Writeln(' Errore, file non trovato. ');
        Readln;
        Exit;
    end;

    AssignFile( iFile, 'prova.txt' ); // TODO: Stabilire il nome del file di input

    Write('Apertura del file di input...' + #9#9#9#9);
    try
        Reset(iFile);
    except
        Writeln('errore.');
        Readln;
        Exit;
    end;
    Writeln('completato.');

    Write('Caricamento dei domini da analizzare...' + #9#9#9);
    while not EoF(iFile) do
    begin
        SetLength( Domains, length(Domains) + 1 );
        Domains[length(Domains) - 1].MailServer := '?';
        Readln( iFile, Domains[length(Domains) - 1].name );
    end;
    Write('completato.' + #9);
    Writeln('[' + IntToStr(Length(Domains) ) + ']');

    CloseFile(iFile);
end;

procedure MXLookup;

    function domainExists(dIndex: Integer; dName: String): Boolean;
    var
        hIndex: Integer;
    begin
        Result := False;
        for hIndex := 0 to Length(Domains[dIndex].Hosts) - 1 do
            if Domains[dIndex].Hosts[hIndex].DNSname = dName then
            begin
                Result := True;
                Break;
            end;
    end;

var
    i, j,
    mxCount: Word;
    DNS:     TIdDNSResolver;
begin
    Write('Creazione di una lista di record probabili...' + #9#9);
    for i := 0 to Length(Domains) - 1 do
        for j := 0 to Length(ExtraDomains) - 1 do
            if not domainExists(i, ExtraDomains[j]) then
            begin
                SetLength(Domains[i].hosts, Length(Domains[i].hosts) + 1);
                Domains[i].Hosts[Length(Domains[i].Hosts) - 1].DNSname := ExtraDomains[j] + '.' + Domains[i].Name;
            end;
    Write('completato.' + #9);
    Writeln('[' + IntToStr( Length(Domains) * Length(ExtraDomains) ) + ']');

    Write('Ricerca e aggiunta dei record MX associati...' + #9#9);
    DNS := TIdDNSResolver.Create;
    DNS.Host := '8.8.8.8';
    DNS.QueryType := [qtMX];
    mxCount := 0;
    for i := 0 to Length(Domains) - 1 do
    begin
        DNS.Resolve( Domains[i].name );
        for j := 0 to DNS.QueryResult.Count - 1 do
            if DNS.QueryResult[j].RecType = qtMX then
            begin
                SetLength( Domains[i].hosts, length(Domains[i].hosts) + 1 );
                Domains[i].hosts[length(Domains[i].hosts) - 1].DNSname := TMXRecord(DNS.QueryResult[j]).ExchangeServer;
            end;
        mxCount := mxCount + DNS.QueryResult.Count;
    end;
    Write('completato.' + #9);
    Writeln('[' + IntToStr( mxCount ) + ']');
end;

procedure NMAP;

    function getFileFromPath(fileName: string): string;
    var
        filePartPtr:   pWideChar;
        filePart,
        fullFilePath:  array[0..255] of char;
    begin
        filePartPtr := @filePart;
        searchPath(nil, pWideChar(fileName), nil, 255, fullFilePath, filePartPtr);
        SetString( Result, PChar(@fullFilePath[0]), Length(fullFilePath) );

        Trim(Result);
    end;

var
    i,
    j,
    k,
    l:      Integer;
    hCount: Word;
    skip:   boolean;
    oFile:  TextFile;
    SEInfo: TShellExecuteInfo;
begin
    AssignFile( oFile, IncludeTrailingPathDelimiter( GetEnvironmentVariable('TEMP') ) + nInputFile);

    Write('Generazione della lista di host da analizzare...' + #9);
    try
        Rewrite(oFile);
    except
        Writeln('errore.');
        Readln;
        Exit;
    end;

    hCount := 0;
    for i := 0 to Length(Domains) - 1 do
        for j := 0 to Length(Domains[i].hosts) - 1 do
        begin
            skip := false;

            for k := 0 to i do
            begin
                for l := 0 to Length(Domains[k].hosts) - 1 do
                    if (Domains[i].hosts[j].DNSname = Domains[k].hosts[l].DNSname) and
                       (k <> i) and (j <> l) then
                    begin
                        skip := true;
                        break;
                    end;

                 if skip then
                    break;
            end;

            if not skip then
            begin
                Writeln(oFile, Domains[i].hosts[j].DNSname);
                inc(hCount);
            end;
        end;
    CloseFile(oFile);
    Write('completato.' + #9);
    Writeln('[' + IntToStr( hCount ) + ']');

    Writeln;
    Writeln('Avvio analisi dei servizi disponibili per host...' + #9#9#9);
    FillChar(SEInfo, sizeof(TShellExecuteInfo), 0);
    SEInfo.cbSize := SizeOf(TShellExecuteInfo);
    with SEInfo do
    begin
        fMask        := SEE_MASK_NOCLOSEPROCESS or SEE_MASK_NO_CONSOLE;
        Wnd          := 0;
        lpFile       := PChar( getFileFromPath('nmap.exe') );
        lpParameters := PChar('-sT -sV -p T:25,80,110,143,443,465,993,995 -Pn'
                        + ' -iL ' + IncludeTrailingPathDelimiter( GetEnvironmentVariable('TEMP') ) + nInputFile
                        + ' -oX ' + IncludeTrailingPathDelimiter( GetEnvironmentVariable('TEMP') ) + nOutputFile) ;
    end;
    ShellExecuteEx(@SEInfo);
    WaitForSingleObject(SEInfo.hProcess, INFINITE); // TODO: Stabilire un timeout?
    Writeln;
    Writeln('Analisi degli host completata.');
end;

procedure parseXML;
var
    ResultXML:  IXMLDOMDocument;
    HostList,
    SrvList:    IXMLDOMNodeList;
    CurHost,
    CurPort:    IXMLDOMNode;
    tmpHost:    String;
    i,
    j,
    k,
    l:          Integer;
begin
    CoInitialize(nil);
    ResultXML := CoDOMDocument.Create;

    // Caricamento dell'XML in memoria
    ResultXML.load( IncludeTrailingPathDelimiter( GetEnvironmentVariable('TEMP') ) + nOutputFile );

    // Selezione dei nodi host
    HostList := ResultXML.selectNodes('nmaprun/host');

    // Parsing dei nodi host
    for i := 0 to HostList.length - 1 do
    begin
        for k := 0 to Length(Domains) - 1 do
        begin
            // Selezione del nodo host
            CurHost := HostList.item[i];

            // Recupero del nome
            tmpHost := VarToStr(CurHost.selectSingleNode('hostnames').selectSingleNode('hostname').attributes.getNamedItem('name').nodeValue);

            for l := 0 to Length(Domains[k].hosts) - 1 do
            begin
                if tmpHost = Domains[k].hosts[l].DNSname then
                begin
                    // Recupero dell'indirizzo IP
                    Domains[k].hosts[l].IP := VarToStr(CurHost.selectSingleNode('address').attributes.getNamedItem('addr').nodeValue);

                    // Selezione dei nodi porta
                    SrvList := CurHost.selectNodes('ports/port');
                    SetLength(Domains[k].hosts[l].Services, SrvList.length);

                    // Parsing dei nodi porta
                    for j := 0 to SrvList.length - 1 do
                    begin
                        // Selezione del nodo porta
                        CurPort := SrvList.item[j];

                        // Recupero del protocollo
                        Domains[k].hosts[l].Services[j].protocol :=  VarToStr(CurPort.attributes.getNamedItem('protocol').nodeValue);
                        // Recupero del numero
                        Domains[k].hosts[l].Services[j].port     :=  WORD(CurPort.attributes.getNamedItem('portid').nodeValue);
                        // Recupero dello stato
                        Domains[k].hosts[l].Services[j].status   :=  VarToStr(CurPort.selectSingleNode('state').attributes.getNamedItem('state').nodeValue);
                        // Recupero del nome
                        Domains[k].hosts[l].Services[j].name     :=  VarToStr(CurPort.selectSingleNode('service').attributes.getNamedItem('name').nodeValue);
                        // Recupero delle informazioni
                        Domains[k].hosts[l].Services[j].info     := '?';
                        if Assigned( CurPort.selectSingleNode('service').attributes.getNamedItem('product') ) then
                        begin
                            Domains[k].hosts[l].Services[j].info :=  VarToStr(CurPort.selectSingleNode('service').attributes.getNamedItem('product').nodeValue);

                            if Assigned( CurPort.selectSingleNode('service').attributes.getNamedItem('version') ) then
                                Domains[k].hosts[l].Services[j].info :=
                                    Domains[k].hosts[l].Services[j].info + ' v'
                                    + VarToStr(CurPort.selectSingleNode('service').attributes.getNamedItem('version').nodeValue);
                            if Assigned( CurPort.selectSingleNode('service').attributes.getNamedItem('extrainfo') ) then
                                Domains[k].hosts[l].Services[j].info :=
                                    Domains[k].hosts[l].Services[j].info + ' - '
                                    + VarToStr(CurPort.selectSingleNode('service').attributes.getNamedItem('extrainfo').nodeValue);
                        end;
                    end;
                end;
            end;
        end;
    end;
end;

procedure buildHTMLReport;

var
    i, j, k:       Word;
    rStream:       TResourceStream;
    sStream:       TStringStream;
    tfReport:      TextFile;
    tmpReport,
    htmlHostTable,
    htmlChartInfo: String;
    MTANames:      Array of String;
    MTACounter:    Array of Byte;

    function split(const strBuf: string; const delimiter: string): tStringList;
    var
        tmpBuf:    string;
        loopCount: word;
    begin
        result := tStringList.create;

        loopCount := 1;
        repeat
            if strBuf[loopCount] = delimiter then
            begin
                result.add( trim(tmpBuf) );
                tmpBuf := '';
            end;
            tmpBuf := tmpBuf + strBuf[loopCount];

            inc(LoopCount);
        until loopCount > length(strBuf);

        result.add( trim(tmpBuf) );
    end;

    function findService(dIndex, hIndex, portNumber: Word): Service;
    var
        tIndex: Integer;
    begin
        for tIndex := 0 to Length(Domains[dIndex].hosts[hIndex].Services) - 1 do
            if Domains[dIndex].hosts[hIndex].Services[tIndex].port = portNumber then
            begin
                Result := Domains[dIndex].hosts[hIndex].Services[tIndex];
                Break;
            end;
    end;

    function findMTA(nMTA: string): ShortInt;
    var
        i: ShortInt;
    begin
        Result := -1;
        for i := 0 to Length(MTANames) - 1 do
            if MTANames[i] = nMTA then
            begin
                Result := i;
                Break;
            end;
    end;

    function stdMTAName(iMTAName: string): string;
    var
        i:        ShortInt;
        isKnown:  Boolean;
    begin
        // Ricerca nel database di MTA conosciuti
        isKnown := False;
        for i := 0 to Length(knownMTA) -1 do
            if AnsiContainsText(iMTAName, knownMTA[i]) then
            begin
                Result  := fullMTANames[i];
                isKnown := True;
                Break;
            end;

        if not isKnown then
            Result   := 'Altro';
    end;

    function knownMostUsedMTA: String;
    var
        i:        ShortInt;
        maxIndex: Byte;
    begin
        // Diminizione di priorità per gli MTA sconosciuti
        for i := 0 to Length(MTANames) - 1 do
            if MTANames[i] = 'Altro' then
                MTACounter[i] := 0;

        maxIndex := 0;
        for i := 0 to Length(MTACounter) - 1 do
            if MTACounter[i] > MTACounter[maxIndex] then
                maxIndex := i;

        Result := MTANames[maxIndex];
    end;

begin
    // Estrazione del report di base dalla memoria
    rStream := TResourceStream.Create(hInstance, 'resHTMLHead', RT_RCDATA);
    sStream := TStringStream.Create;
    sStream.CopyFrom(rStream, rStream.Size);
    tmpReport := sStream.DataString;

    // Creazione del file di output
    AssignFile(tfReport, 'report.html');
    Rewrite(tfReport);

    // Ricerca del Mail Server di dominio per priorità
    for i := 0 to Length(Domains) - 1 do
    begin
        SetLength(MTANames,   0);
        SetLength(MTACounter, 0);

        for j := 0 to Length(Domains[i].Hosts) - 1 do
        begin
            if (findService(i, j, 110).status = 'open') and
               (findService(i, j, 110).info <> '?')     then
                Domains[i].Hosts[j].MailServer := stdMTAName( findService(i, j, 110).info )
            else if (findService(i, j, 143).status = 'open') and
                    (findService(i, j, 143).info <> '?')     then
                Domains[i].Hosts[j].MailServer := stdMTAName( findService(i, j, 143).info )
            else if (findService(i, j, 995).status = 'open') and
                    (findService(i, j, 995).info <> '?')     then
                Domains[i].Hosts[j].MailServer := stdMTAName( findService(i, j, 995).info )
            else if (findService(i, j, 993).status = 'open') and
                    (findService(i, j, 993).info <> '?')     then
                Domains[i].Hosts[j].MailServer := stdMTAName( findService(i, j, 993).info )
            else if (findService(i, j, 25).status = 'open') and
                    (findService(i, j, 25).info <> '?')     then
                Domains[i].Hosts[j].MailServer := stdMTAName( findService(i, j, 25).info )
            else if (findService(i, j, 465).status = 'open') and
                    (findService(i, j, 465).info <> '?')     then
                Domains[i].Hosts[j].MailServer := stdMTAName( findService(i, j, 465).info )
            else if (findService(i, j, 80).status = 'open') and
                    (findService(i, j, 80).info <> '?')     then
                Domains[i].Hosts[j].MailServer := stdMTAName( findService(i, j, 80).info )
            else if (findService(i, j, 443).status = 'open') and
                    (findService(i, j, 443).info <> '?')     then
                Domains[i].Hosts[j].MailServer := stdMTAName( findService(i, j, 443).info )
            else
                Domains[i].Hosts[j].MailServer := 'Altro';

            if findMTA(Domains[i].Hosts[j].MailServer) = -1 then
            begin
                SetLength( MTANames,   Length(MTANames)   + 1 );
                SetLength( MTACounter, Length(MTACounter) + 1 );

                MTANames[Length(MTANames)     - 1] := Domains[i].Hosts[j].MailServer;
                MTACounter[Length(MTACounter) - 1] := 1;
            end
            else
                inc( MTACounter[findMTA(Domains[i].Hosts[j].MailServer)] );
        end;
        Domains[i].MailServer := knownMostUsedMTA;
    end;

    // Preparazione delle statistiche per il grafico
    SetLength(MTANames,   0);
    SetLength(MTACounter, 0);
    for i := 0 to Length(Domains) - 1 do
        if findMTA(Domains[i].MailServer) = -1 then
        begin
            SetLength( MTANames,   Length(MTANames)   + 1 );
            SetLength( MTACounter, Length(MTACounter) + 1 );

            MTANames[Length(MTANames)     - 1] := Domains[i].MailServer;
            MTACounter[Length(MTACounter) - 1] := 1;
        end
        else
            inc( MTACounter[findMTA(Domains[i].MailServer)] );

    htmlChartInfo :=
        'var chart;'                + sLineBreak +
			  'var legend;'               + sLineBreak +
			  'var chartData = ['         + sLineBreak;
    for i := 0 to Length(MTANames) - 1 do
    begin
        htmlChartInfo :=
            htmlChartInfo + '{' +
            'mailserver: "' + MTANames[i] + '",'            + sLineBreak +
            'value: '       + IntToStr(MTACounter[i]) + ',' + sLineBreak +
            '}';
        if i < (Length(MTANames) - 1) then
            htmlChartInfo := htmlChartInfo + ',';
    end;
    htmlChartInfo :=                             htmlChartInfo +
			  '];'                                      + sLineBreak +

		    'AmCharts.ready(function () {'            + sLineBreak +
				    'chart = new AmCharts.AmPieChart();'  + sLineBreak +
            'chart.dataProvider = chartData;'     + sLineBreak +
            'chart.titleField = "mailserver";'    + sLineBreak +
            'chart.valueField = "value";'         + sLineBreak +
            'chart.outlineColor = "#FFFFFF";'     + sLineBreak +
            'chart.outlineAlpha = 0.8;'           + sLineBreak +
            'chart.outlineThickness = 2;'         + sLineBreak +

            'chart.write("chartdiv");'            + sLineBreak +
		    '});'                                     + sLineBreak;

    htmlHostTable := '<table id="domains" style="width: 95%; height: auto; margin: 20px auto 0 auto">' + sLineBreak;
    for i := 0 to Length(Domains) - 1 do
    begin
        htmlHostTable :=
            htmlHostTable +
            '<tr>' +
                '<td colspan="5" class="domain">' +
                    Domains[i].Name + ' (MTA: ' + Domains[i].MailServer + ')' +
                '</td>' +
            '</tr>' +
            sLineBreak;
        for j := 0 to Length(Domains[i].Hosts) - 1 do
        begin
            htmlHostTable :=
                htmlHostTable +
                '<tr>' +
                    '<td class="colspacer"></td>' +
                    '<td colspan="4" class="server">' +
                        Domains[i].Hosts[j].DNSname +
                        ' (IP: ' + Domains[i].Hosts[j].IP + ' - MTA: ' + Domains[i].Hosts[j].MailServer + ')' +
                    '</td>' +
                '</tr>' +
                sLineBreak;
            for k := 0 to Length(Domains[i].Hosts[j].Services) - 1 do
                htmlHostTable :=
                    htmlHostTable +
                    '<tr>' +
                        '<td class="colspacer"></td>' +
                        '<td class="colspacer"></td>' +
                        '<td class="' + Domains[i].Hosts[j].Services[k].status[1] + 'port">' +
                            AnsiUpperCase(Domains[i].Hosts[j].Services[k].protocol) + ': ' +
                            IntToStr(Domains[i].Hosts[j].Services[k].port) + ' (' +
                            Domains[i].Hosts[j].Services[k].name + ')' +
                        '</td>' +
                        '<td class="' + Domains[i].Hosts[j].Services[k].status[1] + 'port">' +
                            'Status: ' + Domains[i].Hosts[j].Services[k].status +
                        '</td>' +
                        '<td class="' + Domains[i].Hosts[j].Services[k].status[1] + 'info">' +
                            'Info: ' + Domains[i].Hosts[j].Services[k].info +
                        '</td>' +
                    '</tr>' +
                    sLineBreak;
        end;
    end;
    htmlHostTable := htmlHostTable + '</table>' + sLineBreak;

    tmpReport := StringReplace(tmpReport, '$$ChartInfo$$', htmlChartInfo, [rfReplaceAll]);
    tmpReport := StringReplace(tmpReport, '$$HostTable$$', htmlHostTable, [rfReplaceAll]);
    Write(tfReport, tmpReport);

    CloseFile(tfReport);
end;

begin
    LoadDomains;
    MXLookup;
    NMAP;
    parseXML;
    buildHTMLReport;

    Readln;
end.
