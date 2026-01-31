#!/usr/local/bin/perl
use strict;
use warnings;
require './zfsaclmanager-lib.pl';
our (%in, %text);

&ReadParse();

my $target = $in{'target'} || '';
my $update_error = '';
my $info;

if ($in{'update_state'}) {
    if ($target ne '') {
        state_set('target', $target);
        my $zfs_opts = zfs_prop_options();
        foreach my $p (keys %$zfs_opts) {
            my $k = "zfs_".$p;
            if (defined $in{$k} && $in{$k} ne '') {
                state_set($k, $in{$k});
            }
        }
        if (defined $in{'base_owner'}) {
            my @bo = _sanitize_user_list($in{'base_owner'});
            state_set('base_owner', join(' ', @bo));
        }
        if (defined $in{'base_group'}) {
            my @bg = _sanitize_user_list($in{'base_group'});
            state_set('base_group', join(' ', @bg));
        }
        state_save();
    }
    print "Content-type: text/plain\n\nOK\n";
    exit;
}

if ($in{'update_acl_users'}) {
    if ($target ne '') {
        my $info_local = detect_target_info($target);
        if (!$info_local->{exists}) {
            print "Content-type: text/plain\n\nERROR: target missing\n";
            exit;
        }
        if (!$info_local->{dataset}) {
            print "Content-type: text/plain\n\nERROR: dataset not found\n";
            exit;
        }
        my $val = $in{'acl_users_set'} || '';
        set_acl_users_for_dataset($info_local->{dataset}, $val);
        state_set('target', $target);
        state_set('acl_users', $val);
        state_save();
    }
    print "Content-type: text/plain\n\nOK\n";
    exit;
}

if ($target ne '') {
    $info = detect_target_info($target);
    if ($in{'update_props'}) {
        if (!$info->{exists}) {
            $update_error = $text{'target_missing'};
        }
        elsif (!$info->{dataset}) {
            $update_error = $text{'err_dataset'} || 'Dataset not found for target';
        }
        else {
            set_profile_for_dataset($info->{dataset}, $in{'profile_set'});
            if (defined $in{'acl_users_set'}) {
                set_acl_users_for_dataset($info->{dataset}, $in{'acl_users_set'});
            }
            my $zfs_opts = zfs_prop_options();
            foreach my $p (keys %$zfs_opts) {
                my $k = "zfs_".$p;
                if (defined $in{$k} && $in{$k} ne '') {
                    set_zfs_prop_for_dataset($info->{dataset}, $p, $in{$k});
                }
            }
            $info = detect_target_info($target);
        }
    }
}

&ui_print_header(undef, $text{'title'}, "");

my $about_html = "<div style='float:right;max-width:45%;color:#555;font-size:90%'>".
    "<b>About ZFS ACL Manager</b><br>".
    "Manages and audits NFSv4 ACLs on ZFS datasets and paths. ".
    "Applies baseline ACLs, adds/removes user ACEs, and can enforce ".
    "recommended ZFS ACL properties. Tested on FreeBSD.".
    "</div>";
print $about_html;
my $ver = our $MODULE_VERSION;
$ver = '1.0 beta' if (!$ver);
print "<div style='margin-top:2px;color:#666'>Version: ".&html_escape($ver)."</div>";
print "<div style='clear:both'></div>";

print &ui_form_start('index.cgi', 'get');
print &ui_table_start($text{'target_title'}, undef, 2);
print &ui_table_row($text{'target'},
    &ui_filebox('target', $target, 60, 0, undef, undef, 0));
print &ui_table_end();
print &ui_form_end([ [ 'detect', $text{'detect'} ] ]);

if ($target ne '') {
    $info ||= detect_target_info($target);
    print &ui_form_start('index.cgi', 'post', undef,
        "onsubmit='return zfsacl_update_submit(this)'");
    print &ui_hidden('target', $info->{target});
    print &ui_hidden('update_props', 1);
    print &ui_table_start($text{'target_info'}, undef, 2);
    if (!$info->{exists}) {
        print &ui_table_row($text{'errors'},
            &html_escape($text{'target_missing'}).": ".&html_escape($target));
        print &ui_table_end();
        print &ui_form_end();
        &ui_print_footer('/', $text{'title'});
        exit;
    }

    my $posix_base = 'N/A';
    my $owner_name = '';
    my $group_name = '';
    if ($info->{posix_uid} ne '') {
        $owner_name = getpwuid($info->{posix_uid}) || '';
    }
    if ($info->{posix_gid} ne '') {
        $group_name = getgrgid($info->{posix_gid}) || '';
    }

    if ($update_error ne '') {
        print &ui_table_row($text{'errors'}, &html_escape($update_error));
    }

    my $state_target = state_get('target', '');
    my $force_refresh = $in{'refresh'} ? 1 : 0;
    my $use_state = ($state_target && $state_target eq $target && !$force_refresh) ? 1 : 0;
    my $has_ds = $info->{dataset} ? 1 : 0;
    my $saved_profile = $use_state ? state_get('profile', '') : '';
    my $profile_sel;
    if ($info->{dataset}) {
        $profile_sel = ($info->{profile} && $info->{profile} eq 'EXEC') ? 'EXEC' : 'MEDIA';
    }
    else {
        $profile_sel = $saved_profile ? $saved_profile : 'MEDIA';
    }
    my @profile_set_opts = (
        [ 'MEDIA', $text{'profile_media'} ],
        [ 'EXEC',  $text{'profile_exec'} ],
    );
    my $profile_select = &ui_select(
        'profile_set', $profile_sel, \@profile_set_opts, 1, 0, 0,
        $has_ds ? 0 : 1,
        "onchange='zfsacl_update_modes()'"
    );

    my $mode_str = "dir=".$info->{mode_dir}." file=".$info->{mode_file};
    my $posix_modes_html = "<span id='posix_modes_val'>".&html_escape($mode_str)."</span>";

    my @acl_selected = ();
    my $acl_source = $info->{acl_users};
    if (!$acl_source && $use_state) {
        $acl_source = state_get('acl_users', '');
    }
    if ($acl_source) {
        @acl_selected = split(/\s+/, $acl_source);
    }
    my %acl_seen = map { $_ => 1 } @acl_selected;
    my $smb_users = list_samba_users();
    my @acl_left_opts = map { [ $_, $_ ] } @acl_selected;
    my @acl_right_list = grep { !$acl_seen{$_} } @$smb_users;
    my @acl_right_opts = map { [ $_, $_ ] } @acl_right_list;
    my $acl_left = &ui_select(
        'acl_users_left', [], \@acl_left_opts, 8, 1, 0, $has_ds ? 0 : 1,
        "style='min-width:200px' ondblclick='acl_users_move(this.form,0);'"
    );
    my $acl_right = &ui_select(
        'acl_users_right', [], \@acl_right_opts, 8, 1, 0, $has_ds ? 0 : 1,
        "style='min-width:200px' ondblclick='acl_users_move(this.form,1);'"
    );
    my $acl_select = "<table class='ui_multi_select'><tr class='ui_multi_select_heads'>".
        "<td><b>$text{'acl_users_policy'}</b></td><td></td><td><b>$text{'samba_users'}</b></td></tr>".
        "<tr class='ui_multi_select_row'><td>$acl_left</td><td></td><td>$acl_right</td></tr></table>".
        &ui_hidden('acl_users_set', join("\n", @acl_selected));

    my $saved_owner = $use_state ? state_get('base_owner', '') : '';
    my $saved_group = $use_state ? state_get('base_group', '') : '';
    my @base_owner_sel = _sanitize_user_list($in{'base_owner'} || $saved_owner || $owner_name);
    my @base_group_sel = _sanitize_user_list($in{'base_group'} || $saved_group || $group_name);
    my $sys_users = list_system_users();
    my $sys_groups = list_system_groups();
    my %owner_seen = map { $_ => 1 } @base_owner_sel;
    my %group_seen = map { $_ => 1 } @base_group_sel;
    my @owner_left_opts = map { [ $_, $_ ] } @base_owner_sel;
    my @group_left_opts = map { [ $_, $_ ] } @base_group_sel;
    my @owner_right_list = grep { !$owner_seen{$_} } @$sys_users;
    my @group_right_list = grep { !$group_seen{$_} } @$sys_groups;
    my @owner_right_opts = map { [ $_, $_ ] } @owner_right_list;
    my @group_right_opts = map { [ $_, $_ ] } @group_right_list;
    my $owner_left = &ui_select(
        'base_owner_left', [], \@owner_left_opts, 3, 1, 0, 0,
        "style='min-width:200px;height:6em' ondblclick='base_owner_move(this.form,0);'"
    );
    my $owner_right = &ui_select(
        'base_owner_right', [], \@owner_right_opts, 3, 1, 0, 0,
        "style='min-width:200px;height:6em' ondblclick='base_owner_move(this.form,1);'"
    );
    my $owner_select = "<table class='ui_multi_select'><tr class='ui_multi_select_heads'>".
        "<td><b>$text{'base_owner_title'}</b></td><td></td><td><b>$text{'system_users'}</b></td></tr>".
        "<tr class='ui_multi_select_row'><td>$owner_left</td><td></td><td>$owner_right</td></tr></table>".
        &ui_hidden('base_owner', join("\n", @base_owner_sel));
    my $group_left = &ui_select(
        'base_group_left', [], \@group_left_opts, 3, 1, 0, 0,
        "style='min-width:200px;height:6em' ondblclick='base_group_move(this.form,0);'"
    );
    my $group_right = &ui_select(
        'base_group_right', [], \@group_right_opts, 3, 1, 0, 0,
        "style='min-width:200px;height:6em' ondblclick='base_group_move(this.form,1);'"
    );
    my $group_select = "<table class='ui_multi_select'><tr class='ui_multi_select_heads'>".
        "<td><b>$text{'base_group_title'}</b></td><td></td><td><b>$text{'system_groups'}</b></td></tr>".
        "<tr class='ui_multi_select_row'><td>$group_left</td><td></td><td>$group_right</td></tr></table>".
        &ui_hidden('base_group', join("\n", @base_group_sel));

    print &ui_table_row($text{'target'}, &html_escape($info->{target}));
    print &ui_table_row($text{'detected_type'}, &html_escape($info->{type}));
    print &ui_table_row($text{'dataset'},
        $info->{dataset} ? &html_escape($info->{dataset}) : 'N/A');
    print &ui_table_row($text{'mountpoint'},
        $info->{mountpoint} ? &html_escape($info->{mountpoint}) : 'N/A');
    print &ui_table_row($text{'profile'}, $profile_select);
    print &ui_table_row($text{'posix_modes'}, $posix_modes_html);
    my $disp_uid = $info->{posix_uid};
    my $disp_gid = $info->{posix_gid};
    if ($base_owner_sel[0]) {
        my $u = getpwnam($base_owner_sel[0]);
        $disp_uid = $u if (defined $u);
    }
    if ($base_group_sel[0]) {
        my $g = getgrnam($base_group_sel[0]);
        $disp_gid = $g if (defined $g);
    }
    if (defined $disp_uid && $disp_uid ne '' && defined $disp_gid && $disp_gid ne '') {
        $posix_base = $disp_uid."/".$disp_gid;
    }
    my $disp_owner_name = '';
    my $disp_group_name = '';
    if ($base_owner_sel[0]) {
        $disp_owner_name = $base_owner_sel[0];
    }
    elsif (defined $disp_uid && $disp_uid ne '') {
        $disp_owner_name = getpwuid($disp_uid) || $owner_name || '';
    }
    if ($base_group_sel[0]) {
        $disp_group_name = $base_group_sel[0];
    }
    elsif (defined $disp_gid && $disp_gid ne '') {
        $disp_group_name = getgrgid($disp_gid) || $group_name || '';
    }
    my $eff_label = $text{'effective_uid_gid'} || 'effective uid/gid';
    my $posix_base_html = "<span style='color:#666;font-size:90%'>".
        &html_escape($eff_label).":</span> ".
        &html_escape($posix_base);
    if ($disp_owner_name ne '' || $disp_group_name ne '') {
        my $name_label = $text{'posix_base_names'} || 'user/group';
        my $name_val = ($disp_owner_name || 'N/A')."/".($disp_group_name || 'N/A');
        $posix_base_html .= "<br><span style='color:#666;font-size:90%'>".
            &html_escape($name_label).": ".&html_escape($name_val).
            "</span>";
    }
    print &ui_table_row($text{'posix_base'}, $posix_base_html);
    my $acl_lines = get_acl_base_lines($info->{target});
    if ($acl_lines && @$acl_lines) {
        my $acl_html = join("<br>", map { &html_escape($_) } @$acl_lines);
        print &ui_table_row($text{'acl_base_lines'} || 'ACL base lines',
            "<span style='color:#666;font-size:90%'>".$acl_html."</span>");
    }
    print &ui_table_span("<b>$text{'acl_users'}</b><br>".$acl_select);
    print &ui_table_span("<b>$text{'base_owner'}</b><br>".$owner_select);
    print &ui_table_span("<b>$text{'base_group'}</b><br>".$group_select);
    print &ui_table_end();

    print "<script>\n".
          "function zfsacl_update_modes(){\n".
          "  var sel = document.getElementById('profile_set');\n".
          "  if(!sel) return;\n".
          "  var v = sel.value;\n".
          "  var txt = (v === 'EXEC') ? 'dir=755 file=755' : 'dir=755 file=644';\n".
          "  var span = document.getElementById('posix_modes_val');\n".
          "  if(span) span.textContent = txt;\n".
          "  var p = document.getElementsByName('profile');\n".
          "  if(p && p.length){ for(var i=0;i<p.length;i++){ p[i].value = v; } }\n".
          "  var f = sel.form;\n".
          "  if (f) {\n".
          "    if (typeof zfsacl_update_submit === 'function') { zfsacl_update_submit(f); }\n".
          "    profile_update_props(f, v);\n".
          "  }\n".
          "}\n".
          "function profile_update_props(f, v){\n".
          "  if(!f) return;\n".
          "  var params = [];\n".
          "  params.push('update_props=1');\n".
          "  var t = f.elements['target'];\n".
          "  if(t && t.value !== undefined){ params.push('target='+encodeURIComponent(t.value)); }\n".
          "  params.push('profile_set='+encodeURIComponent(v || ''));\n".
          "  var acl = f.elements['acl_users_set'];\n".
          "  if(acl && acl.value !== undefined){ params.push('acl_users_set='+encodeURIComponent(acl.value)); }\n".
          "  for(var i=0;i<f.elements.length;i++){\n".
          "    var e = f.elements[i];\n".
          "    if(!e || !e.name) continue;\n".
          "    if(e.name.indexOf('zfs_') === 0){\n".
          "      params.push(encodeURIComponent(e.name)+'='+encodeURIComponent(e.value));\n".
          "    }\n".
          "  }\n".
          "  if (window.fetch) {\n".
          "    fetch('index.cgi', {\n".
          "      method: 'POST',\n".
          "      headers: {'Content-Type':'application/x-www-form-urlencoded'},\n".
          "      body: params.join('&')\n".
          "    });\n".
          "  }\n".
          "}\n".
          "function zfs_props_update_state(f){\n".
          "  if(!f) return;\n".
          "  var params = [];\n".
          "  params.push('update_state=1');\n".
          "  var t = f.elements['target'];\n".
          "  if(t && t.value !== undefined){ params.push('target='+encodeURIComponent(t.value)); }\n".
          "  for(var i=0;i<f.elements.length;i++){\n".
          "    var e = f.elements[i];\n".
          "    if(!e || !e.name) continue;\n".
          "    if(e.name.indexOf('zfs_') === 0){\n".
          "      params.push(encodeURIComponent(e.name)+'='+encodeURIComponent(e.value));\n".
          "    }\n".
          "  }\n".
          "  if (window.fetch) {\n".
          "    fetch('index.cgi', {\n".
          "      method: 'POST',\n".
          "      headers: {'Content-Type':'application/x-www-form-urlencoded'},\n".
          "      body: params.join('&')\n".
          "    });\n".
          "  }\n".
          "}\n".
          "function zfsacl_update_submit(f){\n".
          "  acl_users_update_hidden(f);\n".
          "  base_owner_update_hidden(f);\n".
          "  base_group_update_hidden(f);\n".
          "  return true;\n".
          "}\n".
          "function acl_users_update_hidden(f){\n".
          "  if(!f || !f.elements['acl_users_left']) return;\n".
          "  var left = f.elements['acl_users_left'];\n".
          "  var vals = [];\n".
          "  for(var i=0;i<left.options.length;i++){ vals.push(left.options[i].value); }\n".
          "  if(f.elements['acl_users_set']){ f.elements['acl_users_set'].value = vals.join(\"\\n\"); }\n".
          "  var u = document.getElementsByName('users');\n".
          "  if(u && u.length){ for(var j=0;j<u.length;j++){ u[j].value = vals.join(' '); } }\n".
          "}\n".
          "function acl_users_update_property(f){\n".
          "  if(!f) return;\n".
          "  var t = f.elements['target'];\n".
          "  if(!t || !t.value) return;\n".
          "  var v = f.elements['acl_users_set'] ? f.elements['acl_users_set'].value : '';\n".
          "  var params = [];\n".
          "  params.push('update_acl_users=1');\n".
          "  params.push('target='+encodeURIComponent(t.value));\n".
          "  params.push('acl_users_set='+encodeURIComponent(v));\n".
          "  if (window.fetch) {\n".
          "    fetch('index.cgi', {\n".
          "      method: 'POST',\n".
          "      headers: {'Content-Type':'application/x-www-form-urlencoded'},\n".
          "      body: params.join('&')\n".
          "    });\n".
          "  }\n".
          "}\n".
          "function acl_users_move(f, dir){\n".
          "  var left = f.elements['acl_users_left'];\n".
          "  var right = f.elements['acl_users_right'];\n".
          "  if(!left || !right) return;\n".
          "  var from = dir ? right : left;\n".
          "  var to = dir ? left : right;\n".
          "  for(var i=0;i<from.options.length;i++){\n".
          "    var o = from.options[i];\n".
          "    if(o.selected){ o.selected=false; to.add(o, 0); i--; }\n".
          "  }\n".
          "  acl_users_update_hidden(f);\n".
          "  acl_users_update_property(f);\n".
          "}\n".
          "function base_owner_update_hidden(f){\n".
          "  if(!f || !f.elements['base_owner_left']) return;\n".
          "  var left = f.elements['base_owner_left'];\n".
          "  var vals = [];\n".
          "  for(var i=0;i<left.options.length;i++){ vals.push(left.options[i].value); }\n".
          "  if(f.elements['base_owner']){ f.elements['base_owner'].value = vals.join(\"\\n\"); }\n".
          "  var all = document.getElementsByName('base_owner');\n".
          "  if(all && all.length){ for(var j=0;j<all.length;j++){ all[j].value = vals.join(\"\\n\"); } }\n".
          "}\n".
          "function base_posix_update_state(f){\n".
          "  if(!f) return;\n".
          "  var t = f.elements['target'];\n".
          "  if(!t || !t.value) return;\n".
          "  var bo = f.elements['base_owner'] ? f.elements['base_owner'].value : '';\n".
          "  var bg = f.elements['base_group'] ? f.elements['base_group'].value : '';\n".
          "  var params = [];\n".
          "  params.push('update_state=1');\n".
          "  params.push('target='+encodeURIComponent(t.value));\n".
          "  params.push('base_owner='+encodeURIComponent(bo));\n".
          "  params.push('base_group='+encodeURIComponent(bg));\n".
          "  if (window.fetch) {\n".
          "    fetch('index.cgi', {\n".
          "      method: 'POST',\n".
          "      headers: {'Content-Type':'application/x-www-form-urlencoded'},\n".
          "      body: params.join('&')\n".
          "    });\n".
          "  }\n".
          "}\n".
          "function base_owner_move(f, dir){\n".
          "  var left = f.elements['base_owner_left'];\n".
          "  var right = f.elements['base_owner_right'];\n".
          "  if(!left || !right) return;\n".
          "  if(dir){\n".
          "    var sel = null;\n".
          "    for(var i=0;i<right.options.length;i++){ if(right.options[i].selected){ sel = right.options[i]; break; } }\n".
          "    if(!sel) return;\n".
          "    for(var j=0;j<left.options.length;j++){ var o = left.options[j]; o.selected=false; right.add(o, 0); j--; }\n".
          "    sel.selected=false; left.add(sel, 0);\n".
          "  }\n".
          "  else{\n".
          "    for(var k=0;k<left.options.length;k++){\n".
          "      var o2 = left.options[k];\n".
          "      if(o2.selected){ o2.selected=false; right.add(o2, 0); k--; }\n".
          "    }\n".
          "  }\n".
          "  base_owner_update_hidden(f);\n".
          "  base_posix_update_state(f);\n".
          "}\n".
          "function base_group_update_hidden(f){\n".
          "  if(!f || !f.elements['base_group_left']) return;\n".
          "  var left = f.elements['base_group_left'];\n".
          "  var vals = [];\n".
          "  for(var i=0;i<left.options.length;i++){ vals.push(left.options[i].value); }\n".
          "  if(f.elements['base_group']){ f.elements['base_group'].value = vals.join(\"\\n\"); }\n".
          "  var all = document.getElementsByName('base_group');\n".
          "  if(all && all.length){ for(var j=0;j<all.length;j++){ all[j].value = vals.join(\"\\n\"); } }\n".
          "}\n".
          "function base_group_move(f, dir){\n".
          "  var left = f.elements['base_group_left'];\n".
          "  var right = f.elements['base_group_right'];\n".
          "  if(!left || !right) return;\n".
          "  if(dir){\n".
          "    var sel = null;\n".
          "    for(var i=0;i<right.options.length;i++){ if(right.options[i].selected){ sel = right.options[i]; break; } }\n".
          "    if(!sel) return;\n".
          "    for(var j=0;j<left.options.length;j++){ var o = left.options[j]; o.selected=false; right.add(o, 0); j--; }\n".
          "    sel.selected=false; left.add(sel, 0);\n".
          "  }\n".
          "  else{\n".
          "    for(var k=0;k<left.options.length;k++){\n".
          "      var o2 = left.options[k];\n".
          "      if(o2.selected){ o2.selected=false; right.add(o2, 0); k--; }\n".
          "    }\n".
          "  }\n".
          "  base_group_update_hidden(f);\n".
          "  base_posix_update_state(f);\n".
          "}\n".
          "function toggle_rights_fields(f){\n".
          "  if(!f || !f.elements['mode']) return;\n".
          "  var show = (f.elements['mode'].value === 'user_rights');\n".
          "  var r1 = document.getElementById('rights_row');\n".
          "  var r2 = document.getElementById('rights_flags_row');\n".
          "  if(r1) r1.style.display = show ? '' : 'none';\n".
          "  if(r2) r2.style.display = show ? '' : 'none';\n".
          "}\n".
          "if (window.addEventListener) {\n".
          "  window.addEventListener('load', function(){\n".
          "    var forms = document.forms;\n".
          "    var f = forms && forms.length ? forms[forms.length-1] : null;\n".
          "    toggle_rights_fields(f);\n".
          "  });\n".
          "}\n".
          "</script>\n";

    my $zfs_props;
    if ($info->{dataset}) {
        $zfs_props = zfs_props_for_dataset($info->{dataset});
        my $zfs_opts = zfs_prop_options();
        my $zfs_rec = zfs_prop_recommended();
        my $rec_label = $text{'recommended_smb'} || 'recommended for use with SMB';
        print &ui_table_start($text{'zfs_props'}, undef, 2);
        foreach my $p (@$zfs_props) {
            my ($key, $val) = @$p;
            my $cell;
            if ($zfs_opts->{$key}) {
                my @opt_list;
                foreach my $opt (@{ $zfs_opts->{$key} }) {
                    my $label = $opt;
                    if ($zfs_rec->{$key} && $zfs_rec->{$key}->{$opt}) {
                        $label .= " ($rec_label)";
                    }
                    push @opt_list, [ $opt, $label ];
                }
                $cell = &ui_select("zfs_$key", $val, \@opt_list, 1, 0, 1, $has_ds ? 0 : 1,
                    "onchange='zfs_props_update_state(this.form)'");
            }
            else {
                $cell = &html_escape($val);
            }
            print &ui_table_row($key, $cell);
        }
        print &ui_table_end();
    }

    # Persist current UI selections on every render so Run doesn't depend on Save
    my $state_profile = ($profile_sel && $profile_sel eq 'EXEC') ? 'EXEC' : 'MEDIA';
    my $state_acl_users = join(" ", @acl_selected);
    my $state_base_owner = join(" ", @base_owner_sel);
    my $state_base_group = join(" ", @base_group_sel);
    state_set('target', $target);
    state_set('profile', $state_profile);
    state_set('acl_users', $state_acl_users);
    state_set('base_owner', $state_base_owner);
    state_set('base_group', $state_base_group);
    my $zfs_opts = zfs_prop_options();
    if ($zfs_props) {
        my %cur = map { $_->[0] => $_->[1] } @$zfs_props;
        foreach my $p (keys %$zfs_opts) {
            my $k = "zfs_".$p;
            my $v = (defined $in{$k} && $in{$k} ne '') ? $in{$k} : $cur{$p};
            state_set($k, $v) if (defined $v && $v ne '');
        }
    }
    else {
        foreach my $p (keys %$zfs_opts) {
            my $k = "zfs_".$p;
            if (defined $in{$k} && $in{$k} ne '') {
                state_set($k, $in{$k});
            }
        }
    }
    state_save();
    print &ui_form_end([ [ 'save', $text{'save'} ] ]);

    my $reset_label = ($text{'mode_reset'} || 'Reset ACL').
        " <span style='color:#c00'>(Removes users!)</span>";
    my @mode_opts = (
        [ 'reset',      $reset_label ],
        [ 'add',        $text{'mode_add'} ],
        [ 'remove',     $text{'mode_remove'} ],
        [ 'audit_acl',  $text{'mode_audit_acl'} ],
        [ 'audit_posix',$text{'mode_audit_posix'} ],
        [ 'user_rights',$text{'mode_user_rights'} ],
    );
    my @rights_opts = (
        [ 'add',    $text{'rights_add'} ],
        [ 'revoke', $text{'rights_revoke'} ],
    );
    my @profile_opts = (
        [ 'AUTO',  $text{'profile_auto'} ],
        [ 'MEDIA', $text{'profile_media'} ],
        [ 'EXEC',  $text{'profile_exec'} ],
        [ 'NONE',  $text{'profile_none'} ],
    );

    print &ui_form_start('apply.cgi', 'post');
    print &ui_hidden('target', $info->{target});
    my $effective_profile = $profile_sel;
    my $users_val = $info->{acl_users} || ($use_state ? state_get('acl_users', '') : '');
    print &ui_hidden('users', $users_val);
    print &ui_hidden('profile', $effective_profile);
    print &ui_hidden('base_owner', join("\n", @base_owner_sel));
    print &ui_hidden('base_group', join("\n", @base_group_sel));
    print &ui_table_start($text{'menu'}, undef, 2);
    print &ui_table_row($text{'mode'},
        &ui_select('mode', $in{'mode'} || 'audit_acl', \@mode_opts, 1, 0, 0, 0,
            "onchange='toggle_rights_fields(this.form)'"));
    my $rec_default = defined $in{'recursive'} ? $in{'recursive'} : 1;
    print &ui_table_row($text{'recursive'},
        &ui_yesno_radio('recursive', $rec_default));
    my $snap_default = defined $in{'snapshot'} ? $in{'snapshot'} : 0;
    my $snap_disabled = ($info->{type} eq 'FILESYSTEM' && $info->{dataset}) ? 0 : 1;
    print &ui_table_row($text{'snapshot'},
        &ui_yesno_radio('snapshot', $snap_default, 1, 0, $snap_disabled));
    print &ui_table_row($text{'dryrun'},
        &ui_yesno_radio('dryrun', $in{'dryrun'} || 0));
    my $keep_default = defined $in{'keep_logs'} ? $in{'keep_logs'} : 0;
    print &ui_table_row($text{'keep_logs'} || 'Keep logs',
        &ui_yesno_radio('keep_logs', $keep_default));
    my $rights_label = ($text{'rights'} || 'Rights action').
        " <span style='color:#666;font-size:90%'>(Applied on ACL user(s) listed in the window above!)</span>";
    print &ui_table_row($rights_label,
        &ui_select('rights', $in{'rights'} || 'add', \@rights_opts), 1, undef,
        [ "id='rights_row' style='display:none'", "" ]);
    my $rights_flags = join(' ',
        &ui_checkbox('write', 1, $text{'write'}, $in{'write'}),
        &ui_checkbox('delete', 1, $text{'delete'}, $in{'delete'}),
        &ui_checkbox('execute', 1, $text{'execute'}, $in{'execute'}),
        &ui_checkbox('create_missing', 1, $text{'create_missing'}, $in{'create_missing'}));
    $rights_flags .= "<div style='color:#666;font-size:90%'>".
        "Hint: Rights modify existing ACL user entries. ".
        "Enable &quot;".$text{'create_missing'}."&quot; if a user has no ACE.".
        "</div>";
    print &ui_table_row($text{'rights_flags'}, $rights_flags, 1, undef,
        [ "id='rights_flags_row' style='display:none'", "" ]);
    print &ui_table_end();
    print &ui_form_end([ [ 'run', $text{'run'} ] ]);
}

&ui_print_footer('/', $text{'title'});
