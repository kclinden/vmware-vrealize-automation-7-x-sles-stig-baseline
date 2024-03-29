control "V-89519" do
  title "The SLES for vRealize audit system must be configured to audit all
attempts to alter the system through sched_setparam."
  desc  "Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

    The list of audited events is the set of events for which audits are to be
generated. This set of events is typically a subset of the list of all events
for which the system is capable of generating audit records.

    DoD has defined the list of events for which the operating system will
provide an audit record generation capability as the following:

    1) Successful and unsuccessful attempts to access, modify, or delete
privileges, security objects, security levels, or categories of information
(e.g., classification levels);

    2) Access actions, such as successful and unsuccessful logon attempts,
privileged activities or other system-level access, starting and ending time
for user access to the system, concurrent logons from different workstations,
successful and unsuccessful accesses to objects, all program initiations, and
all direct access to the information system;

    3) All account creations, modifications, disabling, and terminations; and

    4) All kernel module load, unload, and restart actions.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000062-GPOS-00031"
  tag "gid": "V-89519"
  tag "rid": "SV-100169r1_rule"
  tag "stig_id": "VRAU-SL-000215"
  tag "fix_id": "F-96261r1_fix"
  tag "cci": ["CCI-000169"]
  tag "nist": ["AU-12 a", "Rev_4"]
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
  tag "check": "Check if the system is configured to audit calls to the
\"sethostname\" system call by running the following command:

# grep -w \"sched_setparam\" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line.

If no line is returned, this is a finding."
  tag "fix": "Run the following command:

echo '-a exit,always -F arch=b64 -S sched_setparam' >> /etc/audit/audit.rules

Or run the following command to implement all logging requirements:

# /etc/dodscript.sh"

describe file("/etc/audit/audit.rules") do
  its("content") { should match %r{-S sched_setparam} }
end

end

