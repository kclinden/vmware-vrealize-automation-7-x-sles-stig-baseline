control "V-89649" do
  title "Files executed through a mail aliases file must be owned by root and
must reside within a directory owned and writable only by root."
  desc  "If a file executed through a mail aliases file is not owned and
writable only by root, it may be subject to unauthorized modification.
Unauthorized modification of files executed through aliases may allow
unauthorized users to attain root privileges."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89649"
  tag "rid": "SV-100299r1_rule"
  tag "stig_id": "VRAU-SL-000575"
  tag "fix_id": "F-96391r1_fix"
  tag "cci": ["CCI-000382"]
  tag "nist": ["CM-7 b", "Rev_4"]
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
  tag "check": "Verify the ownership of files referenced within the sendmail
aliases file:

# more /etc/aliases

Examine the aliases file for any directories or paths used:

# ls -lL <directory or file path>

Check the owner for any paths referenced.

If the file or parent directory is not owned by \"root\", this is a finding."
  tag "fix": "Edit the /etc/aliases file (alternatively, /usr/lib/sendmail.cf).
Locate the entries executing a program. They will appear similar to the
following line:

Aliasname: : /usr/local/bin/ls (or some other program name)

Ensure \"root\" owns the programs and the directory or directories they reside
in by using the \"chown\" command to change owner to \"root\":

# chown root <file or directory name>"
end

