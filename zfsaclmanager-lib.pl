use strict;
use warnings;
use WebminCore;

our (%config, %text);
init_config();
do './ui-lib.pl' if (-r 'ui-lib.pl');

$ENV{PATH} = "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin";

our $MODULE_VERSION    = '1.0 beta';
our $ZFS_PROFILE_PROP    = 'org.zfsguru:profile';
our $ZFS_ACL_USERS_PROP  = 'org.zfsguru:acl_users';
our @ZFS_PROP_LIST       = qw(acltype aclinherit aclmode xattr atime);
our %ZFS_PROP_OPTIONS    = (
    acltype    => [ qw(nfsv4 posix off) ],
    aclinherit => [ qw(discard noallow restricted passthrough passthrough-x) ],
    aclmode    => [ qw(discard groupmask passthrough restricted) ],
    xattr      => [ qw(sa on off) ],
    atime      => [ qw(on off) ],
);
our %ZFS_PROP_RECOMMENDED = (
    acltype    => { nfsv4 => 1 },
    aclinherit => { passthrough => 1 },
    aclmode    => { passthrough => 1 },
    xattr      => { sa => 1 },
    atime      => { off => 1 },
);

sub state_get
{
    my ($key, $default) = @_;
    my $k = "state_".$key;
    return exists $config{$k} ? $config{$k} : $default;
}

sub state_set
{
    my ($key, $value) = @_;
    my $k = "state_".$key;
    $config{$k} = $value;
}

sub state_save
{
    &save_module_config(\%config);
}

sub _quote_shell
{
    my ($s) = @_;
    $s =~ s/'/'"'"'/g;
    return "'$s'";
}

sub _normalize_path
{
    my ($p) = @_;
    return '' if (!defined $p);
    $p =~ s{/\z}{} if (length($p) > 1);
    return $p;
}

sub _run_cmd_mod
{
    my ($cmd) = @_;
    my $out = &backquote_command("$cmd 2>/dev/null");
    $out =~ s/\s+\z//;
    return $out;
}

sub _sanitize_user_list
{
    my ($val) = @_;
    my @raw = split(/[\0,\s]+/, ($val || ''));
    my %seen;
    my @users;
    foreach my $u (@raw) {
        next if ($u eq '');
        next if ($u !~ /^[a-zA-Z0-9._-]+$/);
        next if ($seen{$u}++);
        push @users, $u;
    }
    return @users;
}

sub get_mountpoints
{
    my %mounts;
    my $out = _run_cmd("mount");
    foreach my $line (split(/\n/, $out)) {
        next if ($line =~ /^\s*$/);
        my @f = split(/\s+/, $line);
        next if (@f < 3);
        my $mp = _normalize_path($f[2]);
        $mounts{$mp} = 1 if ($mp ne '');
    }
    return \%mounts;
}

sub dataset_for_mountpoint
{
    my ($mp) = @_;
    $mp = _normalize_path($mp);
    return undef if (!$mp);
    my $out = _run_cmd("zfs list -H -o name,mountpoint");
    foreach my $line (split(/\n/, $out)) {
        next if ($line =~ /^\s*$/);
        my ($ds, $mpp) = split(/\s+/, $line, 2);
        next if (!defined $mpp);
        $mpp = _normalize_path($mpp);
        return $ds if ($mpp eq $mp);
    }
    return undef;
}

sub resolve_dataset_from_path
{
    my ($path) = @_;
    $path = _normalize_path($path);
    return (undef, undef) if (!$path);
    my $out = _run_cmd("zfs list -H -o name,mountpoint -t filesystem");
    my $best_len = -1;
    my ($best_ds, $best_mp) = (undef, undef);
    foreach my $line (split(/\n/, $out)) {
        next if ($line =~ /^\s*$/);
        my ($ds, $mp) = split(/\s+/, $line, 2);
        next if (!defined $mp);
        $mp = _normalize_path($mp);
        next if ($mp eq '' || $mp eq '-');
        my $match = ($path eq $mp);
        if (!$match) {
            my $prefix = ($mp eq '/') ? '/' : $mp.'/';
            $match = (index($path, $prefix) == 0);
        }
        if ($match) {
            my $len = length($mp);
            if ($len > $best_len) {
                $best_len = $len;
                $best_ds = $ds;
                $best_mp = $mp;
            }
        }
    }
    return ($best_ds, $best_mp);
}

sub detect_profile_from_dataset
{
    my ($ds) = @_;
    return 'MEDIA' if (!$ds);
    my $val = _run_cmd("zfs get -H -o value $ZFS_PROFILE_PROP "._quote_shell($ds));
    $val = uc($val || '');
    return ($val eq 'EXEC') ? 'EXEC' : 'MEDIA';
}

sub set_profile_for_dataset
{
    my ($ds, $profile) = @_;
    return 0 if (!$ds);
    $profile = uc($profile || '');
    return 0 if ($profile ne 'MEDIA' && $profile ne 'EXEC');
    my $prop = $ZFS_PROFILE_PROP."=".$profile;
    _run_cmd("zfs set "._quote_shell($prop)." "._quote_shell($ds));
    return 1;
}

sub get_acl_users_for_dataset
{
    my ($ds) = @_;
    return '' if (!$ds);
    my $val = _run_cmd("zfs get -H -o value $ZFS_ACL_USERS_PROP "._quote_shell($ds));
    return '' if (!$val || $val eq '-');
    return $val;
}

sub set_acl_users_for_dataset
{
    my ($ds, $val) = @_;
    return 0 if (!$ds);
    my @users = _sanitize_user_list($val);
    if (!@users) {
        _run_cmd("zfs inherit "._quote_shell($ZFS_ACL_USERS_PROP)." "._quote_shell($ds));
        return 1;
    }
    my $line = join(' ', @users);
    my $prop = $ZFS_ACL_USERS_PROP."=".$line;
    _run_cmd("zfs set "._quote_shell($prop)." "._quote_shell($ds));
    return 1;
}

sub list_smb_group_users
{
    my @users;
    my $line = _run_cmd("getent group smbuser");
    if (!$line) {
        $line = _run_cmd("pw group show smbuser");
    }
    if ($line) {
        if ($line =~ /:(?:[^:]*:){2}(.+)$/) {
            @users = split(/,/, $1);
        }
    }
    elsif (-r '/etc/group') {
        if (open my $fh, '<', '/etc/group') {
            while (my $l = <$fh>) {
                chomp $l;
                next if ($l !~ /^smbuser:/);
                if ($l =~ /:(?:[^:]*:){2}(.+)$/) {
                    @users = split(/,/, $1);
                }
                last;
            }
            close $fh;
        }
    }
    my %seen;
    my @clean;
    foreach my $u (@users) {
        next if ($u eq '');
        next if ($u !~ /^[a-zA-Z0-9._-]+$/);
        next if ($seen{$u}++);
        push @clean, $u;
    }
    return \@clean;
}

sub list_samba_users
{
    my @users;
    my @cmds;
    if (-r '/usr/local/etc/smb4.conf') {
        push @cmds, "pdbedit -L -s /usr/local/etc/smb4.conf";
    }
    if (-r '/usr/local/etc/smb.conf') {
        push @cmds, "pdbedit -L -s /usr/local/etc/smb.conf";
    }
    push @cmds, "pdbedit -L";
    foreach my $cmd (@cmds) {
        my $out = _run_cmd($cmd);
        foreach my $line (split(/\n/, $out)) {
            next if ($line =~ /^\s*$/);
            if ($line =~ /^([^:]+):/) {
                push @users, $1;
            }
        }
        last if (@users);
    }
    if (!@users) {
        my @st_cmds;
        if (-r '/usr/local/etc/smb4.conf') {
            push @st_cmds, "samba-tool -s /usr/local/etc/smb4.conf user list";
        }
        if (-r '/usr/local/etc/smb.conf') {
            push @st_cmds, "samba-tool -s /usr/local/etc/smb.conf user list";
        }
        push @st_cmds, "samba-tool user list";
        foreach my $cmd (@st_cmds) {
            my $out = _run_cmd($cmd);
            foreach my $line (split(/\n/, $out)) {
                $line =~ s/^\s+|\s+$//g;
                next if ($line eq "");
                push @users, $line;
            }
            last if (@users);
        }
    }
    if (!@users) {
        my $fallback = list_smb_group_users();
        @users = @$fallback if ($fallback);
    }
    my %seen;
    my @clean;
    foreach my $u (@users) {
        next if ($u eq '');
        next if ($u !~ /^[a-zA-Z0-9._-]+$/);
        next if ($seen{$u}++);
        push @clean, $u;
    }
    return \@clean;
}

sub list_system_users
{
    my @users;
    my $out = _run_cmd("getent passwd");
    if ($out) {
        foreach my $line (split(/\n/, $out)) {
            next if ($line =~ /^\s*$/);
            my ($u) = split(/:/, $line, 2);
            push @users, $u if ($u);
        }
    }
    elsif (-r '/etc/passwd') {
        if (open my $fh, '<', '/etc/passwd') {
            while (my $line = <$fh>) {
                chomp $line;
                my ($u) = split(/:/, $line, 2);
                push @users, $u if ($u);
            }
            close $fh;
        }
    }
    my %seen;
    my @clean;
    foreach my $u (@users) {
        next if ($u eq '');
        next if ($u !~ /^[a-zA-Z0-9._-]+$/);
        next if ($seen{$u}++);
        push @clean, $u;
    }
    return \@clean;
}

sub list_system_groups
{
    my @groups;
    my $out = _run_cmd("getent group");
    if ($out) {
        foreach my $line (split(/\n/, $out)) {
            next if ($line =~ /^\s*$/);
            my ($g) = split(/:/, $line, 2);
            push @groups, $g if ($g);
        }
    }
    elsif (-r '/etc/group') {
        if (open my $fh, '<', '/etc/group') {
            while (my $line = <$fh>) {
                chomp $line;
                my ($g) = split(/:/, $line, 2);
                push @groups, $g if ($g);
            }
            close $fh;
        }
    }
    my %seen;
    my @clean;
    foreach my $g (@groups) {
        next if ($g eq '');
        next if ($g !~ /^[a-zA-Z0-9._-]+$/);
        next if ($seen{$g}++);
        push @clean, $g;
    }
    return \@clean;
}

sub profile_modes
{
    my ($profile) = @_;
    $profile = uc($profile || '');
    return ('755', '755') if ($profile eq 'EXEC');
    return ('755', '644');
}

sub zfs_props_for_dataset
{
    my ($ds) = @_;
    return [] if (!$ds);
    my @rows;
    foreach my $p (@ZFS_PROP_LIST) {
        my $v = _run_cmd("zfs get -H -o value $p "._quote_shell($ds));
        $v = "(unsupported/unknown)" if ($v eq '');
        push @rows, [ $p, $v ];
    }
    return \@rows;
}

sub zfs_prop_options
{
    return \%ZFS_PROP_OPTIONS;
}

sub zfs_prop_recommended
{
    return \%ZFS_PROP_RECOMMENDED;
}

sub set_zfs_prop_for_dataset
{
    my ($ds, $prop, $val) = @_;
    return 0 if (!$ds || !$prop);
    my $opts = zfs_prop_options();
    return 0 if (!$opts->{$prop});
    return 0 if (!defined $val || $val eq '');
    my %allowed = map { $_ => 1 } @{ $opts->{$prop} };
    return 0 if (!$allowed{$val});
    my $propstr = $prop."=".$val;
    _run_cmd("zfs set "._quote_shell($propstr)." "._quote_shell($ds));
    return 1;
}

sub detect_target_info
{
    my ($target) = @_;
    my %info = (
        target    => $target,
        exists    => 0,
        type      => 'OTHER',
        dataset   => '',
        mountpoint=> '',
        profile   => 'NONE',
        acl_users => '',
        posix_uid => '',
        posix_gid => '',
        mode_dir  => '755',
        mode_file => '644',
    );

    return \%info if (!$target);
    $info{exists} = (-e $target) ? 1 : 0;
    return \%info if (!$info{exists});

    my $mounts = get_mountpoints();
    if ($mounts->{_normalize_path($target)}) {
        $info{type} = 'FILESYSTEM';
        $info{mountpoint} = _normalize_path($target);
        $info{dataset} = dataset_for_mountpoint($info{mountpoint}) || '';
    }
    elsif (-d $target) {
        $info{type} = 'DIRECTORY';
    }
    elsif (-f $target) {
        $info{type} = 'FILE';
    }

    if (!$info{dataset}) {
        my ($ds, $mp) = resolve_dataset_from_path($target);
        $info{dataset} = $ds if ($ds);
        $info{mountpoint} = $mp if ($mp);
    }

    if ($info{dataset}) {
        $info{profile} = detect_profile_from_dataset($info{dataset});
        $info{acl_users} = get_acl_users_for_dataset($info{dataset});
    }

    my ($mode_dir, $mode_file) = profile_modes($info{profile});
    $info{mode_dir} = $mode_dir;
    $info{mode_file} = $mode_file;

    my @st = stat($target);
    if (@st) {
        $info{posix_uid} = $st[4];
        $info{posix_gid} = $st[5];
    }

    return \%info;
}

#
# Runtime engine (Perl port of acl_manager.sh.orig)
#
our ($TARGET, $TYPE, $DATASET, $MOUNTPOINT);
our ($PROFILE, $DRY_RUN);
our ($POSIX_UID, $POSIX_GID, $POSIX_OWNER, $POSIX_GROUP);
our ($DIR_OWNER_PERMS, $DIR_GROUP_PERMS, $DIR_EVERY_PERMS);
our ($FILE_OWNER_PERMS, $FILE_GROUP_PERMS, $FILE_EVERY_PERMS);
our ($DIR_USER_PERMS, $FILE_USER_PERMS);
our ($DIR_FLAGS, $FILE_FLAGS);
our ($MODE_DIR, $MODE_FILE);
our ($REC_ACLTYPE, $REC_ACLINHERIT, $REC_ACLMODE, $REC_XATTR, $REC_ATIME);
our ($ENFORCE_USERS_NL, $REMOVE_USERS_NL);
our ($modified_mask, $LAST_MOD_MASK);
our ($PROGRESS_EVERY);
our (%STAT, @RUN_LOG);
our ($RUN_LOG_FH, $RUN_LOG_FILE);
our ($UR_MODE, $UR_ADD, $UR_REM, $UR_CREATE_FLAG);

sub _log_line
{
    my ($msg) = @_;
    push @RUN_LOG, $msg;
    if ($RUN_LOG_FH) {
        print $RUN_LOG_FH $msg."\n";
    }
}

sub _cmd_str
{
    my (@args) = @_;
    return join(" ", map { _quote_shell($_) } @args);
}

sub run_setfacl
{
    my (@args) = @_;
    if ($DRY_RUN) {
        _log_line("DRY-RUN: setfacl "._cmd_str(@args));
        return 0;
    }
    my $cmd = "setfacl "._cmd_str(@args);
    my $out = &backquote_command("$cmd 2>&1");
    my $rc = $? >> 8;
    if ($rc) {
        _log_line("ERROR: $cmd failed (rc=$rc)");
        $out =~ s/\s+\z//;
        _log_line("ERROR: $out") if ($out ne '');
    }
    return $rc;
}

sub _cmd_out
{
    my ($cmd) = @_;
    my $out = &backquote_command("$cmd 2>/dev/null");
    my $rc = $? >> 8;
    return ($rc, $out);
}

sub _run_cmd
{
    my ($cmd) = @_;
    my $out = &backquote_command("$cmd 2>/dev/null");
    $out =~ s/\s+\z//;
    return $out;
}

sub normalize_mode_str
{
    my ($s) = @_;
    $s =~ s/^0+// if (defined $s);
    return $s || "0";
}

sub reset_stats
{
    %STAT = (
        stat_scanned           => 0,
        stat_dirs              => 0,
        stat_files             => 0,
        stat_dirs_modified     => 0,
        stat_files_modified    => 0,
        stat_acl_normalized    => 0,
        stat_dup_users_removed => 0,
        stat_users_added       => 0,
        stat_users_removed     => 0,
        stat_zfs_props_changed => 0,
        stat_missing_objects   => 0,
        stat_acl_read_errors   => 0,
        stat_user_rights_changed => 0,
        stat_userace_missing   => 0,
    );
    $modified_mask = 0;
    $LAST_MOD_MASK = 0;
}

sub decode_modified_mask
{
    my ($m) = @_;
    my $out = "";
    $out .= "POSIX+"  if ($m & 1);
    $out .= "ACL+"    if ($m & 2);
    $out .= "ADD+"    if ($m & 4);
    $out .= "REMOVE+" if ($m & 8);
    $out .= "RIGHTS+" if ($m & 16);
    $out =~ s/\+$//;
    return $out eq "" ? "NONE" : $out;
}

sub init_config_run
{
    # Baseline profile templates (see set_media_profile / set_exec_profile)
    our ($MEDIA_DIR_OWNER_PERMS, $MEDIA_DIR_GROUP_PERMS, $MEDIA_DIR_EVERY_PERMS);
    our ($MEDIA_FILE_OWNER_PERMS, $MEDIA_FILE_GROUP_PERMS, $MEDIA_FILE_EVERY_PERMS);
    our ($MEDIA_FILE_USER_PERMS, $MEDIA_DIR_USER_PERMS);
    our ($EXEC_DIR_OWNER_PERMS, $EXEC_DIR_GROUP_PERMS, $EXEC_DIR_EVERY_PERMS);
    our ($EXEC_FILE_OWNER_PERMS, $EXEC_FILE_GROUP_PERMS, $EXEC_FILE_EVERY_PERMS);
    our ($EXEC_FILE_USER_PERMS, $EXEC_DIR_USER_PERMS);

    $MEDIA_DIR_OWNER_PERMS = "rwxp--aARWcCos";
    $MEDIA_DIR_GROUP_PERMS = "r-xp--a-R-c--s";
    $MEDIA_DIR_EVERY_PERMS = "r-xp--a-R-c--s";
    $MEDIA_FILE_OWNER_PERMS = "rw-p--aARWcCos";
    $MEDIA_FILE_GROUP_PERMS = "r--p--a-R-c--s";
    $MEDIA_FILE_EVERY_PERMS = "r--p--a-R-c--s";
    $MEDIA_FILE_USER_PERMS = "rw-pDdaARWcCos";
    $MEDIA_DIR_USER_PERMS = "rwxpDdaARWcCos";

    $EXEC_DIR_OWNER_PERMS = "rwxp--aARWcCos";
    $EXEC_DIR_GROUP_PERMS = "r-xp--a-R-c--s";
    $EXEC_DIR_EVERY_PERMS = "r-xp--a-R-c--s";
    $EXEC_FILE_OWNER_PERMS = "rwxp--aARWcCos";
    $EXEC_FILE_GROUP_PERMS = "r-xp--a-R-c--s";
    $EXEC_FILE_EVERY_PERMS = "r-xp--a-R-c--s";
    $EXEC_FILE_USER_PERMS = "rwxpDdaARWcCos";
    $EXEC_DIR_USER_PERMS = "rwxpDdaARWcCos";

    $PROFILE = "MEDIA";
    set_media_profile();

    $DIR_FLAGS = "fd-----";
    $FILE_FLAGS = "-------";

    $REC_ACLTYPE = "nfsv4";
    $REC_ACLINHERIT = "passthrough";
    $REC_ACLMODE = "passthrough";
    $REC_XATTR = "sa";
    $REC_ATIME = "off";
    $PROGRESS_EVERY = 50;
}

sub set_media_profile
{
    our ($MEDIA_DIR_OWNER_PERMS, $MEDIA_DIR_GROUP_PERMS, $MEDIA_DIR_EVERY_PERMS);
    our ($MEDIA_FILE_OWNER_PERMS, $MEDIA_FILE_GROUP_PERMS, $MEDIA_FILE_EVERY_PERMS);
    our ($MEDIA_FILE_USER_PERMS, $MEDIA_DIR_USER_PERMS);
    $DIR_OWNER_PERMS = $MEDIA_DIR_OWNER_PERMS;
    $DIR_GROUP_PERMS = $MEDIA_DIR_GROUP_PERMS;
    $DIR_EVERY_PERMS = $MEDIA_DIR_EVERY_PERMS;
    $FILE_OWNER_PERMS = $MEDIA_FILE_OWNER_PERMS;
    $FILE_GROUP_PERMS = $MEDIA_FILE_GROUP_PERMS;
    $FILE_EVERY_PERMS = $MEDIA_FILE_EVERY_PERMS;
    $DIR_USER_PERMS = $MEDIA_DIR_USER_PERMS;
    $FILE_USER_PERMS = $MEDIA_FILE_USER_PERMS;
    $MODE_DIR = "755";
    $MODE_FILE = "644";
}

sub set_exec_profile
{
    our ($EXEC_DIR_OWNER_PERMS, $EXEC_DIR_GROUP_PERMS, $EXEC_DIR_EVERY_PERMS);
    our ($EXEC_FILE_OWNER_PERMS, $EXEC_FILE_GROUP_PERMS, $EXEC_FILE_EVERY_PERMS);
    our ($EXEC_FILE_USER_PERMS, $EXEC_DIR_USER_PERMS);
    $DIR_OWNER_PERMS = $EXEC_DIR_OWNER_PERMS;
    $DIR_GROUP_PERMS = $EXEC_DIR_GROUP_PERMS;
    $DIR_EVERY_PERMS = $EXEC_DIR_EVERY_PERMS;
    $FILE_OWNER_PERMS = $EXEC_FILE_OWNER_PERMS;
    $FILE_GROUP_PERMS = $EXEC_FILE_GROUP_PERMS;
    $FILE_EVERY_PERMS = $EXEC_FILE_EVERY_PERMS;
    $DIR_USER_PERMS = $EXEC_DIR_USER_PERMS;
    $FILE_USER_PERMS = $EXEC_FILE_USER_PERMS;
    $MODE_DIR = "755";
    $MODE_FILE = "755";
}

sub apply_profile
{
    if ($PROFILE eq "MEDIA") {
        set_media_profile();
    }
    elsif ($PROFILE eq "EXEC") {
        set_exec_profile();
    }
    else {
        set_media_profile();
    }
}

sub get_acl_safe
{
    my ($p) = @_;
    return (1, undef) if (!-e $p);
    my ($rc, $out) = _cmd_out("getfacl -q "._quote_shell($p));
    return ($rc, $out);
}

sub get_acl_base_lines
{
    my ($p) = @_;
    my ($rc, $out) = get_acl_safe($p);
    return [] if ($rc);
    my %keep;
    my @users;
    foreach my $line (split(/\n/, $out || "")) {
        $line =~ s/^\s+|\s+$//g;
        next if ($line eq '' || $line =~ /^#/);
        my ($who) = split(/:/, $line, 2);
        next if (!$who);
        if ($who eq 'owner@' || $who eq 'group@' || $who eq 'everyone@') {
            $keep{$who} = $line;
        }
        elsif ($who eq 'user') {
            push @users, $line;
        }
    }
    my @out_lines;
    push @out_lines, $keep{'owner@'} if ($keep{'owner@'});
    push @out_lines, $keep{'group@'} if ($keep{'group@'});
    push @out_lines, $keep{'everyone@'} if ($keep{'everyone@'});
    push @out_lines, @users if (@users);
    return \@out_lines;
}

sub extract_unique_users
{
    my ($acl) = @_;
    my %seen;
    my @out;
    foreach my $line (split(/\n/, $acl || "")) {
        $line =~ s/^\s+|\s+$//g;
        next if ($line !~ /^user:([^:]+):/);
        my $u = $1;
        next if ($seen{$u}++);
        push @out, $u;
    }
    return join("\n", @out);
}

sub merge_unique_users_nl
{
    my ($list) = @_;
    my %seen;
    my @out;
    foreach my $u (split(/\n/, $list || "")) {
        next if ($u eq "");
        next if ($seen{$u}++);
        push @out, $u;
    }
    return join("\n", @out);
}

sub subtract_users_nl
{
    my ($list, $rm_list) = @_;
    my %rm;
    foreach my $u (split(/\n/, $rm_list || "")) {
        next if ($u eq "");
        $rm{$u} = 1;
    }
    my @out;
    foreach my $u (split(/\n/, $list || "")) {
        next if ($u eq "");
        push @out, $u if (!$rm{$u});
    }
    return join("\n", @out);
}

sub users_nl_to_csv
{
    my ($list) = @_;
    my @u = grep { $_ ne "" } split(/\n/, $list || "");
    return join(",", @u);
}

sub count_dup_users
{
    my ($acl) = @_;
    my %u;
    foreach my $line (split(/\n/, $acl || "")) {
        $line =~ s/^\s+|\s+$//g;
        next if ($line !~ /^user:([^:]+):/);
        $u{$1}++;
    }
    my $c = 0;
    foreach my $k (keys %u) {
        $c++ if ($u{$k} > 1);
    }
    return $c;
}

sub user_exists_in_acl
{
    my ($acl, $user) = @_;
    foreach my $line (split(/\n/, $acl || "")) {
        $line =~ s/^\s+|\s+$//g;
        return 1 if ($line =~ /^user:\Q$user\E:/);
    }
    return 0;
}

sub acl_precheck
{
    my ($mode, $isdir, $acl, $reqcsv) = @_;
    my $op = $isdir ? $DIR_OWNER_PERMS : $FILE_OWNER_PERMS;
    my $gp = $isdir ? $DIR_GROUP_PERMS : $FILE_GROUP_PERMS;
    my $ep = $isdir ? $DIR_EVERY_PERMS : $FILE_EVERY_PERMS;
    my $up = $isdir ? $DIR_USER_PERMS : $FILE_USER_PERMS;
    my $want_flags = $isdir ? $DIR_FLAGS : $FILE_FLAGS;

    my %req;
    foreach my $u (split(/,/, $reqcsv || "")) {
        next if ($u eq "");
        $req{$u} = 1;
    }

    my %count;
    my %ok_user;
    my %uc;
    my ($ok_owner, $ok_group, $ok_every) = (0, 0, 0);
    my $bad = 0;

    foreach my $line (split(/\n/, $acl || "")) {
        $line =~ s/\r//g;
        $line =~ s/^\s+|\s+$//g;
        next if ($line eq "" || $line =~ /^#/);
        my @a = split(/:/, $line);
        my $subj = $a[0] // "";
        if ($subj eq "owner@" || $subj eq "group@" || $subj eq "everyone@") {
            $count{$subj}++;
            if ($mode eq "strict" && $count{$subj} > 1) { $bad = 1; }
            my $perms = $a[1] // "";
            my $flags = $a[2] // "";
            my $ok_flags = ($flags eq $want_flags || $flags =~ /^fdi/ || $flags =~ /^fd[i-]*/);
            if ($subj eq "owner@" && $perms eq $op && $ok_flags) { $ok_owner = 1; next; }
            if ($subj eq "group@" && $perms eq $gp && $ok_flags) { $ok_group = 1; next; }
            if ($subj eq "everyone@" && $perms eq $ep && $ok_flags) { $ok_every = 1; next; }
            $bad = 1 if ($mode eq "strict");
            next;
        }
        if ($subj eq "user") {
            if ($mode eq "baseline") { $bad = 1; next; }
            my $user = $a[1] // "";
            my $perms = $a[2] // "";
            my $flags = $a[3] // "";
            $uc{$user}++;
            my $ok_flags = ($flags eq $want_flags || $flags =~ /^fdi/ || $flags =~ /^fd[i-]*/);
            if ($uc{$user} > 1) { $bad = 1; }
            if ($mode eq "strict" && !$req{$user}) { $bad = 1; next; }
            if ($perms eq $up && $ok_flags) { $ok_user{$user} = 1; next; }
            $bad = 1 if ($mode eq "strict");
            next;
        }
        $bad = 1;
    }

    if (!$ok_owner || !$ok_group || !$ok_every) { $bad = 1; }
    foreach my $u (keys %req) {
        $bad = 1 if (!$ok_user{$u});
    }
    return $bad ? 0 : 1;
}

sub build_user_ace_list
{
    my ($users_nl, $isdir) = @_;
    my @u = grep { $_ ne "" } split(/\n/, $users_nl || "");
    my @aces;
    foreach my $u (@u) {
        if ($isdir) {
            push @aces, "user:$u:$DIR_USER_PERMS:$DIR_FLAGS:allow";
        }
        else {
            push @aces, "user:$u:$FILE_USER_PERMS:$FILE_FLAGS:allow";
        }
    }
    return join(",", @aces);
}

sub apply_baseline_and_users
{
    my ($obj, $isdir, $users_nl) = @_;
    run_setfacl("-b", $obj);
    if ($isdir) {
        my $base = "owner\@:$DIR_OWNER_PERMS:$DIR_FLAGS:allow,".
                   "group\@:$DIR_GROUP_PERMS:$DIR_FLAGS:allow,".
                   "everyone\@:$DIR_EVERY_PERMS:$DIR_FLAGS:allow";
        my $users_aces = build_user_ace_list($users_nl, 1);
        my $set = $users_aces ? "$base,$users_aces" : $base;
        run_setfacl("-m", $set, $obj);
    }
    else {
        my $base = "owner\@:$FILE_OWNER_PERMS:$FILE_FLAGS:allow,".
                   "group\@:$FILE_GROUP_PERMS:$FILE_FLAGS:allow,".
                   "everyone\@:$FILE_EVERY_PERMS:$FILE_FLAGS:allow";
        my $users_aces = build_user_ace_list($users_nl, 0);
        my $set = $users_aces ? "$base,$users_aces" : $base;
        run_setfacl("-m", $set, $obj);
    }
}

sub normalize_acl_if_bad
{
    my ($obj, $acltxt, $isdir, $enf_nl, $rm_nl, $strict) = @_;
    my $req_nl = $enf_nl || "";
    if ($rm_nl) {
        $req_nl = subtract_users_nl($req_nl, $rm_nl);
    }
    my $reqcsv = users_nl_to_csv($req_nl);
    if ($strict) {
        return 1 if (acl_precheck("strict", $isdir, $acltxt, $reqcsv));
    }
    else {
        return 1 if (acl_precheck("policy", $isdir, $acltxt, $reqcsv));
    }
    my $dup = count_dup_users($acltxt);
    $STAT{stat_dup_users_removed} += $dup if ($dup > 0);

    my $users_nl = "";
    if ($strict) {
        $users_nl = $req_nl;
    }
    else {
        my $exist_nl = extract_unique_users($acltxt);
        $users_nl = merge_unique_users_nl(join("\n", grep { $_ ne "" } ($exist_nl, $req_nl)));
        $users_nl = subtract_users_nl($users_nl, $rm_nl) if ($rm_nl);
    }
    apply_baseline_and_users($obj, $isdir, $users_nl);
    $STAT{stat_acl_normalized}++;
    return 0;
}

sub reset_acl_baseline_only
{
    my ($obj, $acltxt, $isdir) = @_;
    return 1 if (acl_precheck("baseline", $isdir, $acltxt, ""));
    my $exist_nl = extract_unique_users($acltxt);
    if ($exist_nl ne "") {
        my $cnt = scalar(grep { $_ ne "" } split(/\n/, $exist_nl));
        $STAT{stat_users_removed} += $cnt;
    }
    my $dup = count_dup_users($acltxt);
    $STAT{stat_dup_users_removed} += $dup if ($dup > 0);
    apply_baseline_and_users($obj, $isdir, "");
    return 0;
}

sub add_users_acl
{
    my ($users, $obj, $acltxt, $isdir) = @_;
    my $add_list = "";
    my $changed = 0;
    foreach my $u (split(/\s+/, $users || "")) {
        next if ($u eq "");
        next if (user_exists_in_acl($acltxt, $u));
        my $ace;
        if ($isdir) {
            $ace = "user:$u:$DIR_USER_PERMS:$DIR_FLAGS:allow";
        }
        else {
            $ace = "user:$u:$FILE_USER_PERMS:$FILE_FLAGS:allow";
        }
        $add_list = $add_list ? "$add_list,$ace" : $ace;
        $STAT{stat_users_added}++;
        $changed = 1;
        $acltxt .= "\nuser:$u:";
    }
    if ($add_list ne "") {
        run_setfacl("-m", $add_list, $obj);
    }
    return $changed ? 0 : 1;
}

sub remove_users_acl_rebuild
{
    my ($users_to_remove, $obj, $acltxt, $isdir) = @_;
    my $existing_nl = extract_unique_users($acltxt);
    return 1 if (!$existing_nl);

    my %rm = map { $_ => 1 } grep { $_ ne "" } split(/\s+/, $users_to_remove || "");
    my @removed;
    foreach my $u (split(/\n/, $existing_nl || "")) {
        push @removed, $u if ($rm{$u});
    }
    return 1 if (!@removed);

    my $removed_list_nl = join("\n", @removed);
    my $removed_cnt = scalar(@removed);
    my $filtered_users_nl = subtract_users_nl($existing_nl, $removed_list_nl);

    my $dup = count_dup_users($acltxt);
    if ($dup == 0) {
        my $reqcsv = users_nl_to_csv($filtered_users_nl);
        if (acl_precheck("policy", $isdir, $acltxt, $reqcsv)) {
            my %rm2 = map { $_ => 1 } @removed;
            my @del;
            foreach my $line (split(/\n/, $acltxt || "")) {
                $line =~ s/^\s+|\s+$//g;
                next if ($line !~ /^user:([^:]+):/);
                my $u = $1;
                push @del, $line if ($rm2{$u});
            }
            if (@del) {
                my $del_list = join(",", @del);
                run_setfacl("-x", $del_list, $obj);
            }
            $STAT{stat_users_removed} += $removed_cnt;
            return 0;
        }
    }

    $STAT{stat_dup_users_removed} += $dup if ($dup > 0);
    apply_baseline_and_users($obj, $isdir, $filtered_users_nl);
    $STAT{stat_users_removed} += $removed_cnt;
    return 0;
}

sub build_user_rights_flags
{
    my ($mode, $w, $d, $x) = @_;
    $UR_ADD = "";
    $UR_REM = "";
    if ($w) {
        if ($mode eq "add") { $UR_ADD .= "wpAW"; }
        else { $UR_REM .= "wpAW"; }
    }
    if ($d) {
        if ($mode eq "add") { $UR_ADD .= "Dd"; }
        else { $UR_REM .= "Dd"; }
    }
    if ($x) {
        if ($mode eq "add") { $UR_ADD .= "x"; }
        else { $UR_REM .= "x"; }
    }
    return 0 if ($UR_ADD eq "" && $UR_REM eq "");
    return 1;
}

sub perm_modify
{
    my ($perms, $add, $rem) = @_;
    my @P = split(/\s+/, "r w x p D d a A R W c C o s");
    my $out = "";
    for (my $i = 0; $i < @P; $i++) {
        my $want = $P[$i];
        my $ch = substr($perms, $i, 1);
        if (index($add, $want) >= 0) { $out .= $want; next; }
        if (index($rem, $want) >= 0) { $out .= "-"; next; }
        $out .= ($ch eq $want) ? $want : "-";
    }
    return $out;
}

sub update_user_rights_acl
{
    my ($users, $obj, $acltxt, $isdir) = @_;
    my $changed = 0;
    my @del_list;
    my @set_list;
    my @create_list;

    foreach my $u (split(/\s+/, $users || "")) {
        next if ($u eq "");
        my $uline = "";
        foreach my $line (split(/\n/, $acltxt || "")) {
            $line =~ s/^\s+|\s+$//g;
            if ($line =~ /^user:\Q$u\E:/) { $uline = $line; last; }
        }
        if ($uline eq "") {
            $STAT{stat_userace_missing}++;
            if ($UR_CREATE_FLAG && $UR_MODE eq "add") {
                my ($base_perms, $flags);
                if ($isdir) { $base_perms = $DIR_USER_PERMS; $flags = $DIR_FLAGS; }
                else { $base_perms = $FILE_USER_PERMS; $flags = $FILE_FLAGS; }
                my $add = $UR_ADD;
                my $rem = $UR_REM;
                if (!$isdir) {
                    $add =~ s/D//g;
                    $rem =~ s/D//g;
                }
                my $new_perms = perm_modify($base_perms, $add, $rem);
                push @create_list, "user:$u:$new_perms:$flags:allow";
                $STAT{stat_user_rights_changed}++;
                $changed = 1;
            }
            next;
        }
        my @parts = split(/:/, $uline);
        my $cur_perms = $parts[2] // "";
        my $add = $UR_ADD;
        my $rem = $UR_REM;
        if (!$isdir) {
            $add =~ s/D//g;
            $rem =~ s/D//g;
        }
        my $new_perms = perm_modify($cur_perms, $add, $rem);
        if ($new_perms ne $cur_perms) {
            push @del_list, $uline;
            if ($isdir) {
                push @set_list, "user:$u:$new_perms:$DIR_FLAGS:allow";
            }
            else {
                push @set_list, "user:$u:$new_perms:$FILE_FLAGS:allow";
            }
            $STAT{stat_user_rights_changed}++;
            $changed = 1;
        }
    }

    if (@create_list) {
        run_setfacl("-m", join(",", @create_list), $obj);
    }
    if (@del_list) {
        run_setfacl("-x", join(",", @del_list), $obj);
    }
    if (@set_list) {
        run_setfacl("-m", join(",", @set_list), $obj);
    }
    return $changed ? 0 : 1;
}

sub posix_reset
{
    my ($p, $isdir) = @_;
    return 2 if (!-e $p);
    if (!defined $isdir) {
        $isdir = (-d $p) ? 1 : 0;
    }
    my $want_uid = $POSIX_UID;
    my $want_gid = $POSIX_GID;
    if (!$MODE_DIR || !$MODE_FILE) {
        if ($PROFILE eq "EXEC") { $MODE_DIR ||= "755"; $MODE_FILE ||= "755"; }
        else { $MODE_DIR ||= "755"; $MODE_FILE ||= "644"; }
    }
    my $want_mode = $isdir ? $MODE_DIR : $MODE_FILE;
    my @st = stat($p);
    return 3 if (!@st);
    my $cur_uid = $st[4];
    my $cur_gid = $st[5];
    my $cur_mode = sprintf("%o", $st[2] & 07777);
    my $cur_mode_n = normalize_mode_str($cur_mode);
    my $want_mode_n = normalize_mode_str($want_mode);
    my $cur_oct = oct($cur_mode_n);
    my $want_oct = oct($want_mode_n);
    my $changed = 0;
    if (defined $want_uid && defined $want_gid) {
        if ($cur_uid != $want_uid || $cur_gid != $want_gid) {
            if (!$DRY_RUN) {
                chown($want_uid, $want_gid, $p) || return 4;
            }
            $changed = 1;
        }
    }
    if ($cur_oct != $want_oct) {
        if (!$DRY_RUN) {
            chmod(oct($want_mode_n), $p) || return 5;
        }
        $changed = 1;
    }
    return $changed ? 0 : 1;
}

sub apply_mode_to_obj
{
    my ($mode, $users, $obj, $isdir, $acltxt) = @_;
    if ($mode eq "reset") {
        if (!reset_acl_baseline_only($obj, $acltxt, $isdir)) { $LAST_MOD_MASK |= 2; }
    }
    elsif ($mode eq "add") {
        if (!normalize_acl_if_bad($obj, $acltxt, $isdir, $ENFORCE_USERS_NL, $REMOVE_USERS_NL, 0)) {
            $LAST_MOD_MASK |= 2;
            my ($rc, $txt) = get_acl_safe($obj); return 1 if ($rc); $acltxt = $txt;
        }
        if (!add_users_acl($users, $obj, $acltxt, $isdir)) { $LAST_MOD_MASK |= 4; }
    }
    elsif ($mode eq "remove") {
        if (!remove_users_acl_rebuild($users, $obj, $acltxt, $isdir)) {
            $LAST_MOD_MASK |= 8;
        }
        else {
            if (!normalize_acl_if_bad($obj, $acltxt, $isdir, $ENFORCE_USERS_NL, $REMOVE_USERS_NL, 0)) {
                $LAST_MOD_MASK |= 2;
            }
        }
    }
    elsif ($mode eq "audit_acl") {
        if (!normalize_acl_if_bad($obj, $acltxt, $isdir, $ENFORCE_USERS_NL, $REMOVE_USERS_NL, 1)) { $LAST_MOD_MASK |= 2; }
    }
    elsif ($mode eq "audit_posix") {
        if (posix_reset($obj) == 0) { $LAST_MOD_MASK |= 1; my ($rc, $txt) = get_acl_safe($obj); return 1 if ($rc); $acltxt = $txt; }
        if (!normalize_acl_if_bad($obj, $acltxt, $isdir, $ENFORCE_USERS_NL, $REMOVE_USERS_NL, 1)) { $LAST_MOD_MASK |= 2; }
    }
    elsif ($mode eq "user_rights") {
        if (!update_user_rights_acl($users, $obj, $acltxt, $isdir)) { $LAST_MOD_MASK |= 16; }
    }
    else {
        return 1;
    }
    return 0;
}

sub handle_object
{
    my ($mode, $users, $obj) = @_;
    $LAST_MOD_MASK = 0;
    my $isdir = (-d $obj) ? 1 : 0;
    my ($rc, $acltxt) = get_acl_safe($obj);
    if ($rc) {
        if ($rc == 1) { $STAT{stat_missing_objects}++; }
        else { $STAT{stat_acl_read_errors}++; }
        return 1;
    }
    if (apply_mode_to_obj($mode, $users, $obj, $isdir, $acltxt)) {
        return 1;
    }
    return ($LAST_MOD_MASK != 0) ? 0 : 1;
}

sub handle_object_with_acl
{
    my ($mode, $users, $obj, $acltxt, $isdir) = @_;
    $LAST_MOD_MASK = 0;
    if (!defined $isdir) {
        $isdir = (-d $obj) ? 1 : 0;
    }
    if (!defined $acltxt || $acltxt eq "") {
        $STAT{stat_acl_read_errors}++;
        return 1;
    }
    if (apply_mode_to_obj($mode, $users, $obj, $isdir, $acltxt)) {
        return 1;
    }
    return ($LAST_MOD_MASK != 0) ? 0 : 1;
}

sub process_acl_block
{
    my ($mode, $users, $obj, $acltxt) = @_;
    $STAT{stat_scanned}++;
    my $isdir = (-d $obj) ? 1 : 0;
    $isdir ? $STAT{stat_dirs}++ : $STAT{stat_files}++;
    if (!handle_object_with_acl($mode, $users, $obj, $acltxt, $isdir)) {
        $modified_mask |= $LAST_MOD_MASK;
        $isdir ? $STAT{stat_dirs_modified}++ : $STAT{stat_files_modified}++;
    }
    if ($PROGRESS_EVERY && ($STAT{stat_scanned} % $PROGRESS_EVERY) == 0) {
        _log_line(sprintf("Processing: %d (dirs_mod:%d files_mod:%d)",
            $STAT{stat_scanned}, $STAT{stat_dirs_modified}, $STAT{stat_files_modified}));
    }
}

sub process_recursive_buffered
{
    my ($mode, $users, $root) = @_;
    my $cmd = "find "._quote_shell($root)." -xdev \\( -type d -o -type f \\) -print0 2>/dev/null | ".
              "xargs -0 getfacl 2>/dev/null";
    open my $fh, "-|", "sh", "-c", $cmd or return 1;
    my ($cur, $acl) = ("", "");
    while (my $line = <$fh>) {
        chomp $line;
        if ($line =~ /^# file: (.*)$/) {
            if ($cur ne "") {
                process_acl_block($mode, $users, $cur, $acl);
            }
            $cur = $1;
            $acl = "";
        }
        else {
            if ($cur ne "") {
                $acl .= $line."\n";
            }
        }
    }
    close $fh;
    if ($cur ne "") {
        process_acl_block($mode, $users, $cur, $acl);
    }
    return 0;
}

sub process_single
{
    my ($mode, $users) = @_;
    $STAT{stat_scanned}++;
    (-d $TARGET) ? $STAT{stat_dirs}++ : $STAT{stat_files}++;
    if (!handle_object($mode, $users, $TARGET)) {
        $modified_mask |= $LAST_MOD_MASK;
        (-d $TARGET) ? $STAT{stat_dirs_modified}++ : $STAT{stat_files_modified}++;
    }
    return 0;
}

sub process_recursive
{
    my ($mode, $users) = @_;
    my $root = $TARGET;
    if ($TYPE eq "FILESYSTEM" && $MOUNTPOINT) {
        $root = $MOUNTPOINT;
    }
    return 0 if (!process_recursive_buffered($mode, $users, $root));
    _log_line("Buffered getfacl failed; no fallback enabled.");
    return 1;
}

sub zfs_get_prop
{
    my ($ds, $p) = @_;
    my ($rc, $out) = _cmd_out("zfs get -H -o value "._quote_shell($p)." "._quote_shell($ds));
    return $out;
}

sub zfs_set_if_needed
{
    my ($p, $want) = @_;
    my $cur = zfs_get_prop($DATASET, $p);
    return 1 if (!$cur || $cur eq $want);
    _log_line("Setting ZFS property: $p=$want (was: $cur)");
    _run_cmd_mod("zfs set "._quote_shell("$p=$want")." "._quote_shell($DATASET));
    $STAT{stat_zfs_props_changed}++;
    return 0;
}

sub enforce_zfs_props_run
{
    return 1 if (!$DATASET);
    _log_line("---- enforce ZFS ACL properties ----");
    my $changed_any = 0;
    zfs_set_if_needed("acltype", $REC_ACLTYPE) && ($changed_any = 1);
    zfs_set_if_needed("aclinherit", $REC_ACLINHERIT) && ($changed_any = 1);
    zfs_set_if_needed("aclmode", $REC_ACLMODE) && ($changed_any = 1);
    zfs_set_if_needed("xattr", $REC_XATTR) && ($changed_any = 1);
    zfs_set_if_needed("atime", $REC_ATIME) && ($changed_any = 1);
    _log_line("ZFS properties already match recommended values.") if (!$changed_any);
    _log_line("------------------------------------");
    return 0;
}

sub load_policy_users
{
    $ENFORCE_USERS_NL = "";
    return "" if (!$DATASET && !$MOUNTPOINT);
    if ($DATASET) {
        my $val = get_acl_users_for_dataset($DATASET);
        if ($val) {
            my @u = split(/\s+/, $val);
            $ENFORCE_USERS_NL = join("\n", @u);
            return $ENFORCE_USERS_NL;
        }
    }
    if ($MOUNTPOINT) {
        my ($rc, $acl) = get_acl_safe($MOUNTPOINT);
        if (!$rc && $acl) {
            $ENFORCE_USERS_NL = extract_unique_users($acl);
            return $ENFORCE_USERS_NL;
        }
    }
    if ($TARGET) {
        my ($rc, $acl) = get_acl_safe($TARGET);
        if (!$rc && $acl) {
            $ENFORCE_USERS_NL = extract_unique_users($acl);
            return $ENFORCE_USERS_NL;
        }
    }
    return "";
}

sub print_summary_run
{
    _log_line("================ SUMMARY ================");
    _log_line("Scanned objects          : $STAT{stat_scanned} (dirs: $STAT{stat_dirs}, files: $STAT{stat_files})");
    _log_line("Directories modified    : $STAT{stat_dirs_modified}");
    _log_line("Files modified          : $STAT{stat_files_modified}");
    _log_line("Bad ACL normalized      : $STAT{stat_acl_normalized}");
    _log_line("Duplicate users removed : $STAT{stat_dup_users_removed}");
    _log_line("Users added             : $STAT{stat_users_added}");
    _log_line("Users removed           : $STAT{stat_users_removed}");
    _log_line("User ACE missing        : $STAT{stat_userace_missing}");
    _log_line("User rights changed     : $STAT{stat_user_rights_changed}");
    _log_line("Missing during scan     : $STAT{stat_missing_objects}");
    _log_line("ACL read errors         : $STAT{stat_acl_read_errors}");
    _log_line("Modification summary    : ".decode_modified_mask($modified_mask));
    if ($TYPE eq "FILESYSTEM" && $DATASET) {
        _log_line("ZFS props changed       : $STAT{stat_zfs_props_changed}");
    }
    _log_line("*** DRY RUN - NO CHANGES WERE APPLIED ***") if ($DRY_RUN);
    _log_line("========================================");
}

sub run_acl_manager
{
    my (%opt) = @_;
    @RUN_LOG = ();
    $RUN_LOG_FH = undef;
    $RUN_LOG_FILE = $opt{log_file} || '';
    if ($RUN_LOG_FILE) {
        if (open my $fh, '>', $RUN_LOG_FILE) {
            $RUN_LOG_FH = $fh;
            my $old = select($RUN_LOG_FH);
            $| = 1;
            select($old);
        }
    }
    init_config_run();
    reset_stats();

    $TARGET = $opt{target} || "";
    $DRY_RUN = $opt{dry_run} ? 1 : 0;

    my $info = detect_target_info($TARGET);
    $TYPE = $info->{type} || "OTHER";
    $DATASET = $info->{dataset} || "";
    $MOUNTPOINT = $info->{mountpoint} || "";

    $PROFILE = $opt{profile} || $info->{profile} || "MEDIA";
    apply_profile();

    $POSIX_UID = $info->{posix_uid} || "";
    $POSIX_GID = $info->{posix_gid} || "";
    $POSIX_OWNER = "";
    $POSIX_GROUP = "";

    if ($opt{base_owner} && $opt{base_group}) {
        my $uid = getpwnam($opt{base_owner});
        my $gid = getgrnam($opt{base_group});
        if (defined $uid && defined $gid) {
            $POSIX_UID = $uid;
            $POSIX_GID = $gid;
            $POSIX_OWNER = $opt{base_owner};
            $POSIX_GROUP = $opt{base_group};
        }
    }

    $ENFORCE_USERS_NL = "";
    $REMOVE_USERS_NL = "";
    load_policy_users();

    my $mode = $opt{mode} || "";
    my $users = $opt{users} || "";
    my @safe_users = _sanitize_user_list($users);
    $users = join(' ', @safe_users);
    if (($mode eq "add" || $mode eq "remove" || $mode eq "user_rights") && $users eq "") {
        _log_line("ERROR: users required for $mode");
        return \@RUN_LOG;
    }
    if ($mode eq "user_rights") {
        $UR_MODE = $opt{rights} || "";
        if ($UR_MODE ne "add" && $UR_MODE ne "revoke") {
            _log_line("ERROR: missing/invalid rights action");
            return \@RUN_LOG;
        }
        if (!build_user_rights_flags($UR_MODE, $opt{write}, $opt{delete}, $opt{execute})) {
            _log_line("ERROR: no rights selected");
            return \@RUN_LOG;
        }
        $UR_CREATE_FLAG = $opt{create_missing} ? 1 : 0;
    }
    if ($opt{snapshot} && $TYPE eq "FILESYSTEM" && $DATASET) {
        my @t = localtime(time());
        my $ts = sprintf("%04d-%02d-%02d_%02d%02d%02d",
            $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0]);
        _run_cmd_mod("zfs snapshot "._quote_shell($DATASET."\@acl-$ts"));
    }
    if ($opt{enforce_zfs}) {
        enforce_zfs_props_run();
    }

    if ($opt{recursive}) { process_recursive($mode, $users); }
    else { process_single($mode, $users); }

    print_summary_run();
    if ($RUN_LOG_FH) {
        close $RUN_LOG_FH;
        $RUN_LOG_FH = undef;
    }
    return \@RUN_LOG;
}

1;
