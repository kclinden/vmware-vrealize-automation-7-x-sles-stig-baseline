control "V-89751" do
  title "The SLES for vRealize must initiate session audits at system start-up."
  desc  "If auditing is enabled late in the start-up process, the actions of
some start-up processes may not be audited. Some audit systems also maintain
state information only available if auditing is enabled before a given process
is created."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000254-GPOS-00095"
  tag "gid": "V-89751"
  tag "rid": "SV-100401r1_rule"
  tag "stig_id": "VRAU-SL-000895"
  tag "fix_id": "F-96493r1_fix"
  tag "cci": ["CCI-001464"]
  tag "nist": ["AU-14 (1)", "Rev_4"]
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
  tag "check": "Check for the \"audit=1\" kernel parameter.

# grep \"audit=1\" /proc/cmdline

If no results are returned, this is a finding."
  tag "fix": "Edit the grub bootloader file /boot/grub/menu.lst by appending
the \"audit=1\" parameter to the kernel boot line.

Reboot the system for the change to take effect."
end

