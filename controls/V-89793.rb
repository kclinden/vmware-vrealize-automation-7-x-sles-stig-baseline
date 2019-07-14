control "V-89793" do
  title "The time synchronization configuration file (such as /etc/ntp.conf)
must be group-owned by root, bin, sys, or system."
  desc  "A synchronized system clock is critical for the enforcement of
time-based policies and the correlation of logs and audit records with other
systems. If an illicit time source is used for synchronization, the integrity
of system logs and the security of the system could be compromised. If the
configuration files controlling time synchronization are not owned by a system
group, unauthorized modifications could result in the failure of time
synchronization."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000355-GPOS-00143"
  tag "gid": "V-89793"
  tag "rid": "SV-100443r1_rule"
  tag "stig_id": "VRAU-SL-001120"
  tag "fix_id": "F-96535r1_fix"
  tag "cci": ["CCI-001891"]
  tag "nist": ["AU-8 (1) (a)", "Rev_4"]
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
  tag "check": "Check the group-ownership of the NTP configuration file:

# ls -lL /etc/ntp.conf

If the group-owner is not \"root\", \"bin\", \"sys\", or \"system\", this is a
finding."
  tag "fix": "Change the group-owner of the NTP configuration file:

# chgrp root /etc/ntp.conf"
end

