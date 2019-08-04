control "V-89819" do
  title "The SLES for vRealize must implement address space layout
randomization to protect its memory from unauthorized code execution."
  desc  "Some adversaries launch attacks with the intent of executing code in
non-executable regions of memory or in memory locations that are prohibited.
Security safeguards employed to protect memory include, for example, data
execution prevention and address space layout randomization. Data execution
prevention safeguards can either be hardware-enforced or software-enforced with
hardware providing the greater strength of mechanism.

    Examples of attacks are buffer overflow attacks.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000433-GPOS-00193"
  tag "gid": "V-89819"
  tag "rid": "SV-100469r1_rule"
  tag "stig_id": "VRAU-SL-001340"
  tag "fix_id": "F-96561r2_fix"
  tag "cci": ["CCI-002824"]
  tag "nist": ["SI-16", "Rev_4"]
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
  tag "check": "Verify \"randomize_va_space\" has not been changed from the
default \"1\" setting.

# sysctl kernel.randomize_va_space

If the return value is not \"kernel.randomize_va_space = 1\", this is a
finding."
  tag "fix": "Run the following command:

#sysctl kernel.randomize_va_space=1"

describe kernel_parameter('kernel.randomize_va_space') do
  its('value') { should eq 1 }
end

end

