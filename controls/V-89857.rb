control "V-89857" do
  title "The SLES for vRealize must generate audit records for all account
creations, modifications, disabling, and termination events."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000476-GPOS-00221"
  tag "gid": "V-89857"
  tag "rid": "SV-100507r1_rule"
  tag "stig_id": "VRAU-SL-001480"
  tag "fix_id": "F-96599r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Determine if execution of the \"usermod\" and \"groupmod\"
executable are audited:

# auditctl -l | egrep '(usermod|groupmod)'

If either \"usermod\" or \"groupmod\" are not listed with a permissions filter
of at least \"x\", this is a finding.

Determine if execution of the \"userdel\" and \"groupdel\" executable are
audited:

# auditctl -l | egrep '(userdel|groupdel)'

If either \"userdel\" or \"groupdel\" are not listed with a permissions filter
of at least \"x\", this is a finding.

Determine if execution of \"useradd\" and \"groupadd\" are audited:

# auditctl -l | egrep '(useradd|groupadd)'

If either \"useradd\" or \"groupadd\" are not listed with a permissions filter
of at least \"x\", this is a finding.

Determine if execution of the \"passwd\" executable is audited:

# auditctl -l | grep “/usr/bin/passwd”

If \"/usr/bin/passwd\" is not listed with a permissions filter of at least
\"x\", this is a finding.

Determine if /etc/passwd, /etc/shadow, /etc/group, and /etc/security/opasswd
are audited for writing:

# auditctl -l | egrep '(/etc/passwd|/etc/shadow|/etc/group|/etc/security/opasswd)'

If any of these are not listed with a permissions filter of at least \"w\",
this is a finding."
  tag "fix": "Configure \"execute\" auditing of the \"usermod\" and
\"groupmod\" executables. Add the following to the /etc/audit/audit.rules file:

-w /usr/sbin/usermod -p x -k usermod
-w /usr/sbin/groupmod -p x -k groupmod

Configure \"execute\" auditing of the \"userdel\" and \"groupdel\" executables.
Add the following to the /etc/audit/audit.rules file:

-w /usr/sbin/userdel -p x -k userdel
-w /usr/sbin/groupdel -p x -k groupdel

Configure \"execute\" auditing of the \"useradd\" and \"groupadd\" executables.
Add the following to audit.rules:

-w /usr/sbin/useradd -p x -k useradd
-w /usr/sbin/groupadd -p x -k groupadd

Configure \"execute\" auditing of the \"passwd\" executable. Add the following
to the aud.rules:

-w /usr/bin/passwd -p x -k passwd

Configure \"write\" auditing of the \"passwd\", \"shadow\", \"group\", and
\"opasswd\" files. Add the following to the /etc/audit/audit.rules file:

-w /etc/passwd -p wa -k passwd
-w /etc/shadow -p wa -k shadow
-w /etc/group -p wa -k group
-w /etc/security/opasswd -p wa -k opasswd

Restart the auditd service:

# service auditd restart

OR

# /etc/dodscript.sh"

#Currently the passwd,shadow,group, and opasswd are broken into two checks each (w/a vs wa)
describe file('/etc/audit/audit.rules') do
  its('content') {should cmp %r{-w /usr/sbin/usermod -p x -k usermod}}
  its('content') {should cmp %r{-w /usr/sbin/groupmod -p x -k groupmod}}
  its('content') {should cmp %r{-w /usr/sbin/userdel -p x -k userdel}}
  its('content') {should cmp %r{-w /usr/sbin/groupdel -p x -k groupdel}}
  its('content') {should cmp %r{-w /usr/sbin/useradd -p x -k useradd}}
  its('content') {should cmp %r{-w /usr/sbin/groupadd -p x -k groupadd}}
  its('content') {should cmp %r{-w /usr/bin/passwd -p x -k passwd}}
  its('content') {should cmp %r{-w /etc/passwd -p w -k passwd}} 
  its('content') {should cmp %r{-w /etc/shadow -p w -k shadow}}  
  its('content') {should cmp %r{-w /etc/group -p w -k group}}  
  its('content') {should cmp %r{-w /etc/security/opasswd -p w -k opasswd}} 
  its('content') {should cmp %r{-w /etc/passwd -p a -k passwd}} 
  its('content') {should cmp %r{-w /etc/shadow -p a -k shadow}}  
  its('content') {should cmp %r{-w /etc/group -p a -k group}}  
  its('content') {should cmp %r{-w /etc/security/opasswd -p a -k opasswd}} 
end

end

