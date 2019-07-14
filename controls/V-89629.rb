control "V-89629" do
  title "The inetd.conf file, xinetd.conf file, and  xinetd.d directory must be
group owned by root, bin, sys, or system."
  desc  "Failure to give ownership of sensitive files or utilities to root
provides the designated owner and unauthorized users with the potential to
access sensitive information or change the system configuration, which could
weaken the system's security posture."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89629"
  tag "rid": "SV-100279r1_rule"
  tag "stig_id": "VRAU-SL-000525"
  tag "fix_id": "F-96371r1_fix"
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
  tag "check": "Check the group-ownership of the \"xinetd\" configuration files
and directories:

# ls -alL /etc/xinetd.conf /etc/xinetd.d

If a file or directory is not group-owned by \"root\", \"bin\", \"sys\", or
\"system\", this is a finding."
  tag "fix": "Change the group-owner of the \"xinetd\" configuration files and
directories:

# chgrp -R root /etc/xinetd.conf /etc/xinetd.d"
end

