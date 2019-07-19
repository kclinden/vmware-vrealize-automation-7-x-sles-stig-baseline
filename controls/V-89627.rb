control "V-89627" do
  title "The xinetd.conf file, and the xinetd.d directory must be owned by root
or bin."
  desc  "Failure to give ownership of sensitive files or utilities to root
provides the designated owner and unauthorized users with the potential to
access sensitive information or change the system configuration, which could
weaken the system's security posture."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89627"
  tag "rid": "SV-100277r1_rule"
  tag "stig_id": "VRAU-SL-000520"
  tag "fix_id": "F-96369r1_fix"
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
  tag "check": "Check the owner of the \"xinetd\" configuration files:

# ls -lL /etc/xinetd.conf
# ls -laL /etc/xinetd.d

This is a finding if any of the above files or directories are not owned by
\"root\" or \"bin\"."
  tag "fix": "Change the owner of the \"xinetd\" configuration files:

# chown root /etc/xinetd.conf /etc/xinetd.d/*"

describe file('/etc/xinetd.conf') do 
  its('owner') {should be 'root'} # doesn't work, wtf...
end

describe directory('/etc/xinetd.d') do 
  its('owner') {should be 'root'}
end


end

