control "V-89763" do
  title "Shared library files must have root ownership."
  desc  " If the operating system were to allow any user to make changes to
software libraries, then those changes might be implemented without undergoing
the appropriate testing and approvals that are part of a robust change
management process.

    This requirement applies to operating systems with software libraries that
are accessible and configurable, as in the case of interpreted languages.
Software libraries also include privileged programs which execute with
escalated privileges. Only qualified and authorized individuals must be allowed
to obtain access to information system components for purposes of initiating
changes, including upgrades and modifications.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000259-GPOS-00100"
  tag "gid": "V-89763"
  tag "rid": "SV-100413r1_rule"
  tag "stig_id": "VRAU-SL-000921"
  tag "fix_id": "F-96505r1_fix"
  tag "cci": ["CCI-001499"]
  tag "nist": ["CM-5 (6)", "Rev_4"]
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
  tag "check": "Verify that that system wide shared library files have root
ownership with the following command:

ls -l /lib /lib64 /usr/lib /usr/lib64 /lib/modules

If any library files are not root owned, this is a finding."
  tag "fix": "For any shared library file that was a finding:

sudo chown root <filename>"
end

