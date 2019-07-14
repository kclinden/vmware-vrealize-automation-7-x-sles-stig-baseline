control "V-89759" do
  title "The SLES for vRealize must protect audit tools from unauthorized
deletion."
  desc  "Protecting audit information also includes identifying and protecting
the tools used to view and manipulate log data. Therefore, protecting audit
tools is necessary to prevent unauthorized operation on audit information.

    Operating systems providing tools to interface with audit information will
leverage user permissions and roles identifying the user accessing the tools
and the corresponding rights the user has in order to make access decisions
regarding the deletion of audit tools.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000258-GPOS-00099"
  tag "gid": "V-89759"
  tag "rid": "SV-100409r1_rule"
  tag "stig_id": "VRAU-SL-000915"
  tag "fix_id": "F-96501r1_fix"
  tag "cci": ["CCI-001495"]
  tag "nist": ["AU-9", "Rev_4"]
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
  tag "check": "The following command will list which audit files on the system
where the ownership has been modified:

# rpm -V audit | grep '^.....U'

If there is output, this is a finding."
  tag "fix": "Run the following command to reset audit permissions to the
correct values:

sudo rpm --setperms audit-1.8-0.34.26"
end

