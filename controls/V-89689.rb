control "V-89689" do
  title "The SLES for vRealize must have IEEE 1394 (Firewire) disabled unless
needed."
  desc  "Firewire is a common computer peripheral interface. Firewire devices
may include storage devices that could be used to install malicious software on
a system or exfiltrate data."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89689"
  tag "rid": "SV-100339r1_rule"
  tag "stig_id": "VRAU-SL-000675"
  tag "fix_id": "F-96431r1_fix"
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
  tag "check": "If the SLES for vRealize needs IEEE 1394 (Firewire), this is
not applicable.

Check if the firewire module is not disabled:

# grep \"install ieee1394 /bin/true\" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*

If no results are returned, this is a finding."
  tag "fix": "Prevent the SLES for vRealize from loading the firewire module:

# echo \"install ieee1394 /bin/true\" >> /etc/modprobe.conf.local"

describe command('grep "install ieee1394 /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*') do
  its('stdout') {should_not eq ''}
end

end

