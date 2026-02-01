#!/usr/local/bin/perl
use strict;
use warnings;
require './zfsaclmanager-lib.pl';
our (%in, %text);

&ReadParse();

sub _run_dir
{
    my $dir = '';
    if (defined(&module_config_directory)) {
        $dir = &module_config_directory();
    }
    if (!$dir) {
        my $p = $0 || '';
        $p =~ s/\\/\//g;
        $p =~ s/\/[^\/]+$// if ($p =~ /\//);
        $dir = $p;
    }
    my $run_dir = $dir ? $dir."/run_logs" : "/tmp/zfsaclmanager_run_logs";
    if (!-d $run_dir) {
        mkdir($run_dir, 0700);
    }
    return $run_dir;
}

sub _read_file
{
    my ($path) = @_;
    return "" if (!$path || !-r $path);
    my $out = "";
    if (open my $fh, '<', $path) {
        local $/ = undef;
        $out = <$fh>;
        close $fh;
    }
    return $out;
}

sub _json_escape
{
    my ($s) = @_;
    $s = "" if (!defined $s);
    $s =~ s/\\/\\\\/g;
    $s =~ s/\"/\\\"/g;
    $s =~ s/\r/\\r/g;
    $s =~ s/\n/\\n/g;
    $s =~ s/\t/\\t/g;
    return $s;
}

sub _summary_only
{
    my ($s) = @_;
    return "" if (!defined $s || $s eq "");
    my @lines = split(/\r?\n/, $s);
    my $start = -1;
    for (my $i = 0; $i < @lines; $i++) {
        if ($lines[$i] =~ /SUMMARY/i) {
            $start = $i;
            last;
        }
    }
    return $s if ($start < 0);
    my @out = @lines[$start .. $#lines];
    return join("\n", @out);
}

sub _js_escape
{
    my ($s) = @_;
    $s = "" if (!defined $s);
    $s =~ s/\\/\\\\/g;
    $s =~ s/'/\\'/g;
    $s =~ s/\r/\\r/g;
    $s =~ s/\n/\\n/g;
    $s =~ s/</\\x3c/g;
    $s =~ s/>/\\x3e/g;
    $s =~ s/&/\\x26/g;
    return $s;
}

sub _build_run_context_html
{
    my (%opt) = @_;
    my $target = $opt{target} || '';
    my $mode = $opt{mode} || '';
    my $profile = $opt{profile} || 'MEDIA';
    my $base_owner = $opt{base_owner} || '';
    my $base_group = $opt{base_group} || '';

    my $info = detect_target_info($target);
    my ($mode_dir, $mode_file) = profile_modes($profile);
    my $run_modes = "dir=$mode_dir file=$mode_file";

    my $disp_uid = $info->{posix_uid};
    my $disp_gid = $info->{posix_gid};
    if ($base_owner) {
        my $u = getpwnam($base_owner);
        $disp_uid = $u if (defined $u);
    }
    if ($base_group) {
        my $g = getgrnam($base_group);
        $disp_gid = $g if (defined $g);
    }
    my $posix_base = (defined $disp_uid && $disp_uid ne '' && defined $disp_gid && $disp_gid ne '') ?
        $disp_uid."/".$disp_gid : 'N/A';
    my $name_owner = $base_owner || ($disp_uid ne '' ? (getpwuid($disp_uid) || '') : '');
    my $name_group = $base_group || ($disp_gid ne '' ? (getgrgid($disp_gid) || '') : '');
    my $posix_names = (($name_owner || 'N/A')."/".($name_group || 'N/A'));

    my $posix_cell = &html_escape($posix_base)." (".&html_escape($posix_names).")";

    my $mode_key = $mode ? "mode_".$mode : "";
    my $mode_label = ($mode_key && $text{$mode_key}) ? $text{$mode_key} : $mode;

    my $html = &ui_table_start($text{'run_context'} || 'Run context', undef, 2);
    $html .= &ui_table_row($text{'mode'}, &html_escape($mode_label));
    $html .= &ui_table_row($text{'target'}, &html_escape($target));
    $html .= &ui_table_row($text{'detected_type'}, &html_escape($info->{type}));
    $html .= &ui_table_row($text{'dataset'},
        $info->{dataset} ? &html_escape($info->{dataset}) : 'N/A');
    $html .= &ui_table_row($text{'mountpoint'},
        $info->{mountpoint} ? &html_escape($info->{mountpoint}) : 'N/A');
    $html .= &ui_table_row($text{'profile'}, &html_escape($profile));
    $html .= &ui_table_row($text{'posix_modes'}, &html_escape($run_modes));
    $html .= &ui_table_row($text{'posix_base'}, $posix_cell);
    my $acl_lines = get_acl_base_lines($target);
    if ($acl_lines && @$acl_lines) {
        my $acl_html = join("<br>", map { &html_escape($_) } @$acl_lines);
        $html .= &ui_table_row($text{'acl_base_lines'} || 'ACL base lines',
            "<span style='color:#666;font-size:90%'>".$acl_html."</span>");
    }
    $html .= &ui_table_end();
    return $html;
}

my $target = $in{'target'} || '';
my $keep_logs = ($in{'keep_logs'} && $in{'keep_logs'} ne '0') ? 1 : 0;

if ($in{'cancel'} && $in{'job'}) {
    my $job = $in{'job'};
    $job =~ s/[^A-Za-z0-9._-]//g;
    my $run_dir = _run_dir();
    my $logf = $run_dir."/".$job.".log";
    my $statusf = $run_dir."/".$job.".status";
    my $pidf = $run_dir."/".$job.".pid";
    my $pid = _read_file($pidf);
    $pid =~ s/\D//g if (defined $pid);
    if ($pid) {
        kill 15, $pid;
    }
    if (open my $lf, '>>', $logf) {
        print $lf "CANCELLED by user\n";
        close $lf;
    }
    if (open my $sf, '>', $statusf) {
        print $sf "cancelled\n";
        close $sf;
    }
    unlink($pidf) if (-e $pidf);
    print "Content-type: text/plain\n\nOK\n";
    exit;
}

if ($in{'cleanup'} && $in{'job'}) {
    if ($keep_logs) {
        print "Content-type: text/plain\n\nSKIP\n";
        exit;
    }
    my $job = $in{'job'};
    $job =~ s/[^A-Za-z0-9._-]//g;
    my $run_dir = _run_dir();
    my $logf = $run_dir."/".$job.".log";
    my $statusf = $run_dir."/".$job.".status";
    my $pidf = $run_dir."/".$job.".pid";
    unlink($logf) if (-e $logf);
    unlink($statusf) if (-e $statusf);
    unlink($pidf) if (-e $pidf);
    print "Content-type: text/plain\n\nOK\n";
    exit;
}

if ($in{'poll'} && $in{'job'}) {
    my $job = $in{'job'};
    $job =~ s/[^A-Za-z0-9._-]//g;
    my $run_dir = _run_dir();
    my $logf = $run_dir."/".$job.".log";
    my $statusf = $run_dir."/".$job.".status";
    my $pidf = $run_dir."/".$job.".pid";
    my $out = _read_file($logf);
    my $done = (-r $statusf) ? 1 : 0;
    my $out_summary = $done ? _summary_only($out) : $out;

    my $json = "{\"done\":".($done ? 1 : 0).",\"output\":\""._json_escape($out_summary)."\"";
    if ($done) {
        my ($base_owner) = split(/\n/, $in{'base_owner'} || '');
        my ($base_group) = split(/\n/, $in{'base_group'} || '');
        my $ctx = _build_run_context_html(
            target     => $target,
            mode       => ($in{'mode'} || ''),
            profile    => ($in{'profile'} || 'MEDIA'),
            base_owner => $base_owner || '',
            base_group => $base_group || ''
        );
        $json .= ",\"context_html\":\""._json_escape($ctx)."\"";
    }
    $json .= "}";
    if ($done && !$keep_logs) {
        unlink($logf) if (-e $logf);
        unlink($statusf) if (-e $statusf);
        unlink($pidf) if (-e $pidf);
    }
    print "Content-type: application/json\n\n".$json;
    exit;
}

&ui_print_header(undef, $text{'title'}, "");

if ($target eq '') {
    print &ui_table_start($text{'errors'}, undef, 1);
    print &ui_table_row($text{'errors'}, &html_escape($text{'err_target'}));
    print &ui_table_end();
    &ui_print_footer('/', $text{'title'});
    exit;
}

my $info = detect_target_info($target);
if (!$info->{exists}) {
    print &ui_table_start($text{'errors'}, undef, 1);
    print &ui_table_row($text{'errors'},
        &html_escape($text{'target_missing'}).": ".&html_escape($target));
    print &ui_table_end();
    &ui_print_footer('/', $text{'title'});
    exit;
}

my $mode = $in{'mode'} || '';

my ($base_owner) = split(/\n/, $in{'base_owner'} || '');
my ($base_group) = split(/\n/, $in{'base_group'} || '');

my $run_profile = $in{'profile'} || $info->{profile} || 'MEDIA';
my $run_dir = _run_dir();
my $job_id = time()."_".$$."_".int(rand(100000));
my $logf = $run_dir."/".$job_id.".log";
my $statusf = $run_dir."/".$job_id.".status";
my $pidf = $run_dir."/".$job_id.".pid";
unlink($logf) if (-e $logf);
unlink($statusf) if (-e $statusf);
unlink($pidf) if (-e $pidf);

my $pid = fork();
if (defined $pid && $pid > 0) {
    if (open my $pf, '>', $pidf) {
        print $pf $pid;
        close $pf;
    }
}
if (defined $pid && $pid == 0) {
    open(STDIN, "<", "/dev/null");
    open(STDOUT, ">", "/dev/null");
    open(STDERR, ">", "/dev/null");
    run_acl_manager(
        target     => $target,
        mode       => $mode,
        users      => ($in{'users'} || ''),
        recursive  => $in{'recursive'} ? 1 : 0,
        dry_run    => $in{'dryrun'} ? 1 : 0,
        snapshot   => $in{'snapshot'} ? 1 : 0,
        profile    => $run_profile,
        base_owner => $base_owner || '',
        base_group => $base_group || '',
        rights     => ($in{'rights'} || ''),
        write      => ($in{'write'} || 0),
        delete     => ($in{'delete'} || 0),
        execute    => ($in{'execute'} || 0),
        create_missing => ($in{'create_missing'} || 0),
        enforce_zfs => 0,
        log_file   => $logf,
    );
    if (open my $sf, '>', $statusf) {
        print $sf "done\n";
        close $sf;
    }
    unlink($pidf) if (-e $pidf);
    exit 0;
}

if (!defined $pid) {
    my $log = run_acl_manager(
        target     => $target,
        mode       => $mode,
        users      => ($in{'users'} || ''),
        recursive  => $in{'recursive'} ? 1 : 0,
        dry_run    => $in{'dryrun'} ? 1 : 0,
        snapshot   => $in{'snapshot'} ? 1 : 0,
        profile    => $run_profile,
        base_owner => $base_owner || '',
        base_group => $base_group || '',
        rights     => ($in{'rights'} || ''),
        write      => ($in{'write'} || 0),
        delete     => ($in{'delete'} || 0),
        execute    => ($in{'execute'} || 0),
        create_missing => ($in{'create_missing'} || 0),
        enforce_zfs => 0,
    );
    my $out = join("\n", @$log);
    print &ui_table_start($text{'output'}, undef, 1);
    print &ui_table_row('',
        "<pre>".&html_escape($out)."</pre>");
    print &ui_table_end();
    print _build_run_context_html(
        target     => $target,
        mode       => $mode,
        profile    => $run_profile,
        base_owner => $base_owner || '',
        base_group => $base_group || ''
    );
}
else {
    print &ui_table_start($text{'output'}, undef, 1);
    print &ui_table_row('',
        "<pre id='run_output'>Processing...</pre>");
    print &ui_table_end();
    print "<div id='run_context' style='display:none'></div>";
    my $js_target = _js_escape($target);
    my $js_mode = _js_escape($mode);
    my $js_profile = _js_escape($run_profile);
    my $js_owner = _js_escape($base_owner || '');
    my $js_group = _js_escape($base_group || '');
    print "<script>\n".
          "var runJob = '"._js_escape($job_id)."';\n".
          "var runDone = false;\n".
          "var keepLogs = ".($keep_logs ? "true" : "false").";\n".
          "var pollParams = 'poll=1&job='+encodeURIComponent(runJob)+".
              "'&target='+encodeURIComponent('".$js_target."')+".
              "'&mode='+encodeURIComponent('".$js_mode."')+".
              "'&profile='+encodeURIComponent('".$js_profile."')+".
              "'&base_owner='+encodeURIComponent('".$js_owner."')+".
              "'&base_group='+encodeURIComponent('".$js_group."')+".
              "'&keep_logs='+encodeURIComponent('".($keep_logs ? 1 : 0)."');\n".
          "function _lastLine(t){\n".
          "  if(!t) return '';\n".
          "  var lines = t.replace(/\\r/g,'').split('\\n');\n".
          "  for(var i=lines.length-1;i>=0;i--){\n".
          "    if(lines[i].trim() !== '') return lines[i];\n".
          "  }\n".
          "  return '';\n".
          "}\n".
          "function pollRun(){\n".
          "  if (!window.fetch) return;\n".
          "  fetch('apply.cgi', {\n".
          "    method: 'POST',\n".
          "    headers: {'Content-Type':'application/x-www-form-urlencoded'},\n".
          "    body: pollParams\n".
          "  }).then(function(r){ return r.json(); }).then(function(data){\n".
          "    var pre = document.getElementById('run_output');\n".
          "    if (pre) {\n".
          "      if (data.done) {\n".
          "        pre.textContent = data.output && data.output.length ? data.output : '';\n".
          "      }\n".
          "      else {\n".
          "        var line = _lastLine(data.output || '');\n".
          "        pre.textContent = line && line.length ? line : 'Processing...';\n".
          "      }\n".
          "    }\n".
          "    if (data.done) {\n".
          "      runDone = true;\n".
          "      if (data.context_html) {\n".
          "        var ctx = document.getElementById('run_context');\n".
          "        if (ctx) { ctx.innerHTML = data.context_html; ctx.style.display = ''; }\n".
          "      }\n".
          "      if (window.runPollTimer) { clearInterval(window.runPollTimer); }\n".
          "    }\n".
          "  }).catch(function(){});\n".
          "}\n".
          "function cleanupLogs(){\n".
          "  if (!runDone || !runJob || keepLogs) return;\n".
          "  var params = 'cleanup=1&job='+encodeURIComponent(runJob)+\n".
          "               '&keep_logs='+encodeURIComponent(keepLogs ? 1 : 0);\n".
          "  if (navigator.sendBeacon) {\n".
          "    try {\n".
          "      var blob = new Blob([params], {type:'application/x-www-form-urlencoded'});\n".
          "      navigator.sendBeacon('apply.cgi', blob);\n".
          "      return;\n".
          "    } catch(e) {}\n".
          "  }\n".
          "  if (window.fetch) {\n".
          "    try {\n".
          "      fetch('apply.cgi', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: params, keepalive: true});\n".
          "      return;\n".
          "    } catch(e) {}\n".
          "  }\n".
          "  try {\n".
          "    var xhr = new XMLHttpRequest();\n".
          "    xhr.open('POST', 'apply.cgi', false);\n".
          "    xhr.setRequestHeader('Content-Type','application/x-www-form-urlencoded');\n".
          "    xhr.send(params);\n".
          "  } catch(e) {}\n".
          "}\n".
          "function cancelRun(){\n".
          "  if (!runJob) return;\n".
          "  var params = 'cancel=1&job='+encodeURIComponent(runJob)+\n".
          "               '&keep_logs='+encodeURIComponent(keepLogs ? 1 : 0);\n".
          "  if (navigator.sendBeacon) {\n".
          "    try {\n".
          "      var blob = new Blob([params], {type:'application/x-www-form-urlencoded'});\n".
          "      navigator.sendBeacon('apply.cgi', blob);\n".
          "      return;\n".
          "    } catch(e) {}\n".
          "  }\n".
          "  if (window.fetch) {\n".
          "    try {\n".
          "      fetch('apply.cgi', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: params, keepalive: true});\n".
          "      return;\n".
          "    } catch(e) {}\n".
          "  }\n".
          "  try {\n".
          "    var xhr = new XMLHttpRequest();\n".
          "    xhr.open('POST', 'apply.cgi', false);\n".
          "    xhr.setRequestHeader('Content-Type','application/x-www-form-urlencoded');\n".
          "    xhr.send(params);\n".
          "  } catch(e) {}\n".
          "}\n".
          "function back_with_cancel(){\n".
          "  if (!runDone) { cancelRun(); }\n".
          "  return true;\n".
          "}\n".
          "pollRun();\n".
          "window.runPollTimer = setInterval(pollRun, 1000);\n".
          "if (window.addEventListener) {\n".
          "  window.addEventListener('beforeunload', function(){\n".
          "    if (!runDone) { cancelRun(); }\n".
          "    cleanupLogs();\n".
          "  });\n".
          "}\n".
          "</script>\n";
}

my $back_tag = (defined $pid && $pid > 0) ? "onsubmit='return back_with_cancel()'" : "";
print &ui_form_start('index.cgi', 'get', undef, $back_tag);
print &ui_hidden('target', $target);
print &ui_hidden('refresh', 1);
print &ui_form_end([ [ 'back', $text{'back'} || 'Back' ] ]);

&ui_print_footer('/', $text{'title'});
