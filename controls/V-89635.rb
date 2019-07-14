control "V-89635" do
  title "The ypbind service must not be running if no network services
utilizing it are enabled."
  desc  "Disabling the \"ypbind\" service ensures the system is not acting as a
client in a NIS or NIS+ domain when not required."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89635"
  tag "rid": "SV-100285r1_rule"
  tag "stig_id": "VRAU-SL-000540"
  tag "fix_id": "F-96377r1_fix"
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
  tag "check": "If network services are using the \"ypbind\" service, this is
not applicable.

To check that the \"ypbind\" service is disabled in system boot configuration,
run the following command:

# chkconfig \"ypbind\" --list

Output should indicate the \"ypbind\" service has either not been installed, or
has been disabled at all run levels, as shown in the example below:

ypbind 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify \"ypbind\" is disabled through current
runtime configuration:

# service ypbind status

If the service is disabled the command will return the following output:

Checking for service ypbind unused

If the service is running, this is a finding."
  tag "fix": "The \"ypbind\" service can be disabled with the following
command:

# chkconfig ypbind off"
end

