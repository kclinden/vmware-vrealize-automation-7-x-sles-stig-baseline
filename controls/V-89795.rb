control "V-89795" do
  title "The time synchronization configuration file (such as /etc/ntp.conf)
must have mode 0640 or less permissive."
  desc  "A synchronized system clock is critical for the enforcement of
time-based policies and the correlation of logs and audit records with other
systems. If an illicit time source is used for synchronization, the integrity
of system logs and the security of the system could be compromised. If the
configuration files controlling time synchronization are not protected,
unauthorized modifications could result in the failure of time synchronization."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000355-GPOS-00143"
  tag "gid": "V-89795"
  tag "rid": "SV-100445r1_rule"
  tag "stig_id": "VRAU-SL-001125"
  tag "fix_id": "F-96537r1_fix"
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
  tag "check": "Check that the mode for the NTP configuration file is not more
permissive than \"0640\":

# ls -l /etc/ntp.conf

If the mode is more permissive than \"0640\", this is a finding."
  tag "fix": "Change the mode of the NTP configuration file to \"0640\" or less
permissive:

# chmod 0640 /etc/ntp.conf"
end

