program pTsubaki;

{$APPTYPE CONSOLE}

{$R *.res}
{$R resources.res}

uses
    Generics.Collections,
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

    Service = class
        protocol,
        name,
        status,
        info:     String;
    end;

    Host = record
        Services:   TDictionary<Word, Service>;
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

const
    nInputFile =  'nmap_input.txt';
    nOutputFile = 'nmap_output.xml';
    nReportFile = 'scan_report.html';
    Ports:        array[0..7] of Word   = (110, 143, 995, 993, 25, 465, 80, 443);
    knownMTA:     array[0..8] of string = ('Google', 'Postini', 'Exchange', 'Lotus', 'MDaemon', 'Postfix', 'Exim', 'Dovecot', 'hMail');
    fullMTANames: array[0..8] of string = ('Google Apps Services', 'Google Postini Services', 'Microsoft Exchange Server',
                                           'IBM Lotus Domino', 'MDaemon Mail Server', 'Postfix', 'Exim', 'Dovecot', 'hMailServer');
    ExtraDomains: array[0..9] of string = ('pop', 'pop3', 'imap', 'imap4', 'pops', 'pop3s', 'imaps', 'imap4s', 'mail', 'webmail');

var
    iFile,
    oFile:         TextFile;

    i, j,
    k, l,
    hCount,
    mxCount:       Integer;

    DNS:           TIdDNSResolver;
    skip:          Boolean;
    SEInfo:        TShellExecuteInfo;

    SrvList,
    HostList:      IXMLDOMNodeList;
    CurHost,
    CurPort:       IXMLDOMNode;
    ResultXML:     IXMLDOMDocument;

    tmpPort:       WORD;
    tmpServ:       Service;
    rStream:       TResourceStream;
    sStream:       TStringStream;
    tfReport:      TextFile;

    tmpList:       TList<Word>;
    Domains:       Array of Domain;
    MTANames:      Array of String;
    MTACounter:    Array of Byte;

    tmpHost,
    tmpDomain,
    tmpReport,
    htmlHostTable,
    htmlChartInfo: String;

    domainIsValid: Boolean;


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

    function split(const strBuf: string; const delimiter: string): tStringList;
    var
        tmpBuf:    string;
        loopCount: Integer;
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
    Writeln('------------------------------------');
    Writeln(' _____           _           _    _');
    Writeln('/__   \___ _   _| |__   __ _| | _(_)');
    Writeln('  / /\/ __| | | | ''_ \ / _` | |/ / |');
    Writeln(' / /  \__ \ |_| | |_) | (_| |   <| |');
    Writeln(' \/   |___/\__,_|_.__/ \__,_|_|\_\_|');
    Writeln('------------------------------------');
    Writeln;

    // Caricamento della lista di domini da analizzare
    // -------------------------------------------------------------------------
    if not FileExists( ParamStr(1) ) then
    begin
        Writeln('Errore: impossibile trovare il file.');
        Readln;
        Exit;
    end;

    AssignFile( iFile, ParamStr(1) );

    Write('Apertura del file di input...' + #9#9#9#9);
    try
        Reset(iFile);
    except
        Writeln('errore.');
        Readln;
        Exit;
    end;
    Writeln('completata.');

    Write('Caricamento dei domini da analizzare...' + #9#9#9);
    DNS := TIdDNSResolver.Create;
    DNS.QueryType := [qtMX];
    DNS.Host := '8.8.8.8';

    while not EoF(iFile) do
    begin
        Readln( iFile, tmpDomain );

        try
            domainIsValid := false;
            DNS.Resolve( tmpDomain );
            for i := 0 to DNS.QueryResult.Count - 1 do
                if DNS.QueryResult[i].RecType = qtMX then
                begin
                    domainIsValid := true;
                    Break;
                end;
            if not domainIsValid then
                raise Exception.Create('No A record found for domain ' + tmpDomain);
        except
            Writeln;
            Write('Attenzione: ' + tmpDomain + ' non sembra essere valido...' + #9);
            Continue;
        end;

        SetLength( Domains, length(Domains) + 1 );
        Domains[length(Domains) - 1].MailServer := '?';
        Domains[length(Domains) - 1].Name := tmpDomain;
    end;
    Write('completato.' + #9);
    Writeln('[' + IntToStr(Length(Domains) ) + ']');

    CloseFile(iFile);
    // -------------------------------------------------------------------------

    // Analisi dei domini caricati
    // -------------------------------------------------------------------------
    Write('Creazione di una lista di record probabili...' + #9#9);

    for i := 0 to Length(Domains) - 1 do
        for j := 0 to Length(ExtraDomains) - 1 do
        begin
            try
                DNS.Resolve( ExtraDomains[j] + '.' + Domains[i].Name );
            except
                continue;
            end;

            if not domainExists(i, ExtraDomains[j]) then
            begin
                SetLength(Domains[i].hosts, Length(Domains[i].hosts) + 1);
                Domains[i].Hosts[Length(Domains[i].Hosts) - 1].DNSname := ExtraDomains[j] + '.' + Domains[i].Name;
            end;
        end;

    Write('completata.' + #9);
    Writeln('[' + IntToStr( Length(Domains) * Length(ExtraDomains) ) + ']');

    Write('Ricerca e aggiunta dei record MX associati...' + #9#9);
    DNS.QueryType := [qtMX];
    mxCount := 0;

    for i := 0 to Length(Domains) - 1 do
    begin
        try
            DNS.Resolve( Domains[i].name );
        except
            continue;
        end;

        for j := 0 to DNS.QueryResult.Count - 1 do
            if DNS.QueryResult[j].RecType = qtMX then
            begin
                inc(mxCount);
                SetLength( Domains[i].hosts, length(Domains[i].hosts) + 1 );
                Domains[i].hosts[length(Domains[i].hosts) - 1].DNSname := TMXRecord(DNS.QueryResult[j]).ExchangeServer;

                if AnsiContainsText(
                            Domains[i].hosts[length(Domains[i].hosts) - 1].DNSname,
                            'google.com' ) or
                   AnsiContainsText(
                            Domains[i].hosts[length(Domains[i].hosts) - 1].DNSname,
                            'googlemail.com' ) then
                begin
                    Domains[i].MailServer := 'Google Apps Services';
                    Break;
                end
                else if AnsiContainsText(
                            Domains[i].hosts[length(Domains[i].hosts) - 1].DNSname,
                            'outlook.com' ) then
                begin
                    Domains[i].MailServer := 'Microsoft Exchange Online';
                    Break;
                end;
            end;
    end;
    Write('completata.' + #9);
    Writeln('[' + IntToStr( mxCount ) + ']');
    // -------------------------------------------------------------------------

    // Analisi degli host ricavati tramite nmap
    // -------------------------------------------------------------------------
    Write('Generazione della lista di host da analizzare...' + #9);

    AssignFile( oFile, IncludeTrailingPathDelimiter( GetEnvironmentVariable('TEMP') ) + nInputFile);
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
    Write('completata.' + #9);
    Writeln('[' + IntToStr( hCount ) + ']');

    Writeln;
    Writeln('Avvio analisi dei servizi disponibili per host...');
    Writeln('-------------------------------------------------------------------');
    FillChar(SEInfo, SizeOf(TShellExecuteInfo), 0);
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
    Writeln('-------------------------------------------------------------------');
    // -------------------------------------------------------------------------

    // Analisi del risultato della scansione
    // -------------------------------------------------------------------------
    Writeln;
    Write('Analisi dei risultati...' + #9#9#9#9);

    CoInitialize(nil);
    ResultXML := CoDOMDocument.Create;

    // Caricamento dell'XML in memoria
    ResultXML.async := false;
    ResultXML.validateOnParse := false;
    ResultXML.load( IncludeTrailingPathDelimiter( GetEnvironmentVariable('TEMP') ) + nOutputFile );
    if ResultXML.parseError.errorCode <> 0 then
    begin
        Writeln('errore.' + #9);
        Writeln;
        Writeln('Problema: ' + ResultXML.parseError.reason);
        Readln;
        Exit;
    end;

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
                    Domains[k].Hosts[l].Services := TDictionary<WORD, Service>.Create;

                    // Parsing dei nodi porta
                    for j := 0 to SrvList.length - 1 do
                    begin
                        // Selezione del nodo porta
                        CurPort := SrvList.item[j];
                        tmpServ := Service.Create;

                        // Recupero del numero
                        tmpPort := Word(CurPort.attributes.getNamedItem('portid').nodeValue);

                        // Recupero del protocollo
                        tmpServ.protocol :=  VarToStr(CurPort.attributes.getNamedItem('protocol').nodeValue);
                        // Recupero dello stato
                        tmpServ.status   :=  VarToStr(CurPort.selectSingleNode('state').attributes.getNamedItem('state').nodeValue);
                        // Recupero del nome
                        tmpServ.name     :=  VarToStr(CurPort.selectSingleNode('service').attributes.getNamedItem('name').nodeValue);
                        // Recupero delle informazioni
                        tmpServ.info     := '?';
                        if Assigned( CurPort.selectSingleNode('service').attributes.getNamedItem('product') ) then
                        begin
                            tmpServ.info :=  VarToStr(CurPort.selectSingleNode('service').attributes.getNamedItem('product').nodeValue);

                            if Assigned( CurPort.selectSingleNode('service').attributes.getNamedItem('version') ) then
                                tmpServ.info :=
                                    tmpServ.info + ' v'
                                    + VarToStr(CurPort.selectSingleNode('service').attributes.getNamedItem('version').nodeValue);
                            if Assigned( CurPort.selectSingleNode('service').attributes.getNamedItem('extrainfo') ) then
                                tmpServ.info :=
                                    tmpServ.info + ' - '
                                    + VarToStr(CurPort.selectSingleNode('service').attributes.getNamedItem('extrainfo').nodeValue);
                        end;

                        Domains[k].Hosts[l].Services.Add(tmpPort, tmpServ);
                    end;
                end;
            end;
        end;
    end;
    Writeln('completata.' + #9);
    // -------------------------------------------------------------------------

    // Produzione del report finale
    // -------------------------------------------------------------------------
    Write('Generazione del report...' + #9#9#9#9);

    // Estrazione del report di base dalla memoria
    rStream := TResourceStream.Create(hInstance, 'resHTMLHead', RT_RCDATA);
    sStream := TStringStream.Create;
    sStream.CopyFrom(rStream, rStream.Size);
    tmpReport := sStream.DataString;

    // Creazione del file di output
    AssignFile(tfReport, nReportFile);
    Rewrite(tfReport);

    // Ricerca del Mail Server di dominio per priorità
    for i := 0 to Length(Domains) - 1 do
    begin
        SetLength(MTANames,   0);
        SetLength(MTACounter, 0);

        for j := 0 to Length(Domains[i].Hosts) - 1 do
        begin
            Domains[i].Hosts[j].MailServer := 'Altro'; // Default ad 'Altro'

            for k := 0 to Length(Ports) - 1 do
                if (Domains[i].Hosts[j].Services.ContainsKey(Ports[k]))     and
                   (Domains[i].Hosts[j].Services[Ports[k]].status = 'open') and
                   (Domains[i].Hosts[j].Services[Ports[k]].info <> '?')     then
                begin
                    Domains[i].Hosts[j].MailServer := stdMTAName( Domains[i].Hosts[j].Services[Ports[k]].info );
                    break;
                end;

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
        if Domains[i].MailServer = '?' then
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
            '<tr name="dName_' + IntToStr(i) + '">' +
                '<td colspan="5" class="domain" ' + 'onClick="javascript:showHosts(''' + IntToStr(i) + ''')"' + '>' +
                    Domains[i].Name + ' (MTA: ' + Domains[i].MailServer + ')' +
                '</td>' +
            '</tr>' +
            sLineBreak;
        for j := 0 to Length(Domains[i].Hosts) - 1 do
        begin
            htmlHostTable :=
                htmlHostTable +
                '<tr name="' + 'dHost_' + IntToStr(i) + '" class="hName" '
                             + 'onClick="javascript:showPorts(''' + IntToStr(i)+ ''', ''' + IntToStr(j) + ''', true)"' + '>' +
                    '<td class="colspacer"></td>' +
                    '<td colspan="4" class="host">' +
                        Domains[i].Hosts[j].DNSname +
                        ' (IP: ' + Domains[i].Hosts[j].IP + ' - MTA: ' + Domains[i].Hosts[j].MailServer + ')' +
                    '</td>' +
                '</tr>' +
                sLineBreak;
            tmpList := TList<WORD>.Create(Domains[i].Hosts[j].Services.Keys);
            tmpList.Sort;
            for k := 0 to tmpList.Count - 1 do
                htmlHostTable :=
                    htmlHostTable +
                    '<tr name="' + 'hPort_' + IntToStr(i) + '_' + IntToStr(j) + '" class="hPort">' +
                        '<td class="colspacer"></td>' +
                        '<td class="colspacer"></td>' +
                        '<td class="' + Domains[i].Hosts[j].Services[tmpList[k]].status[1] + 'port">' +
                            AnsiUpperCase(Domains[i].Hosts[j].Services[tmpList[k]].protocol) + ': ' +
                            IntToStr(tmpList[k]) + ' (' +
                            Domains[i].Hosts[j].Services[tmpList[k]].name + ')' +
                        '</td>' +
                        '<td class="' + Domains[i].Hosts[j].Services[tmpList[k]].status[1] + 'port">' +
                            'Status: ' + Domains[i].Hosts[j].Services[tmpList[k]].status +
                        '</td>' +
                        '<td class="' + Domains[i].Hosts[j].Services[tmpList[k]].status[1] + 'info">' +
                            'Info: ' + Domains[i].Hosts[j].Services[tmpList[k]].info +
                        '</td>' +
                    '</tr>' +
                    sLineBreak;
        end;
        if ( i <> (Length(Domains) - 1) ) then
            htmlHostTable := htmlHostTable +'<tr name="dSpacer"><td colspan="5" class="rowspacer"></tr>' + sLineBreak;
    end;
    htmlHostTable := htmlHostTable + '</table>' + sLineBreak;

    tmpReport := StringReplace(tmpReport, '$$ChartInfo$$', htmlChartInfo, [rfReplaceAll]);
    tmpReport := StringReplace(tmpReport, '$$HostTable$$', htmlHostTable, [rfReplaceAll]);
    Write(tfReport, tmpReport);

    CloseFile(tfReport);
    Writeln('completata.' + #9);

    // Apertura del report a video
    ShellExecute(0, 'open', nReportFile, nil, nil, SW_SHOWNORMAL);
    // -------------------------------------------------------------------------

    Writeln;
    Writeln('Esecuzione completata, premere invio terminare.');
    Readln;
end.
