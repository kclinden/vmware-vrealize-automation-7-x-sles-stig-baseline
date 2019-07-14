control "V-89755" do
  title "The SLES for vRealize must protect audit tools from unauthorized
access."
  desc  "Protecting audit information also includes identifying and protecting
the tools used to view and manipulate log data. Therefore, protecting audit
tools is necessary to prevent unauthorized operation on audit information.

    Operating systems providing tools to interface with audit information will
leverage user permissions and roles identifying the user accessing the tools
and the corresponding rights the user enjoys in order to make access decisions
regarding the access to audit tools.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000256-GPOS-00097"
  tag "gid": "V-89755"
  tag "rid": "SV-100405r1_rule"
  tag "stig_id": "VRAU-SL-000905"
  tag "fix_id": "F-96497r1_fix"
  tag "cci": ["CCI-001493"]
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
have permissions different from what is expected by the RPM database:

# rpm -V audit | grep '^.M'

If there is any output, for each file or directory found, compare the
RPM-expected permissions with the permissions on the file or directory:

# rpm -q --queryformat \"[%{FILENAMES} %{FILEMODES:perms}\
]\" audit | grep [filename]
# ls -lL [filename]

If the existing permissions are more permissive than those expected by RPM,
this is a finding."
  tag "fix": "Run the following command to reset audit permissions to the
correct values:

sudo rpm --setperms audit-1.8-0.34.26"
end

